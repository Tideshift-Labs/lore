// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-119 Step A: `idempotency_key` fixture conformance (CR-032 PIN-1) and the
//! `aggregate_version` v1 width pin (CR-032 F-032-4: an 8-byte big-endian u64
//! ordinal plus 0..=120 identity bytes, total 8..=128 bytes).
//!
//! # Idempotency-key conformance (non-ignored, pure, no Postgres)
//!
//! Loads `idempotency-key.json` relative to `CARGO_MANIFEST_DIR` and fails
//! loudly -- not `#[ignore]`, not a skip -- if the fixture is absent, per the
//! WP-119 Step A brief: "FAIL if absent, never skip." As of this writing the
//! fixture exists (fixture_set_version 2, added 2026-09-03, closing blocker
//! B2), so these tests are expected to run and pass.
//!
//! Two independent proofs, not one calling the other and comparing to itself:
//!
//! - [`idempotency_key_manual_preimage_matches_the_fixtures_own_preimage_hex`]
//!   rebuilds one vector's preimage by hand from the fixture's own algorithm
//!   description and checks it against the fixture's *own* recorded
//!   `preimage_hex`/`idempotency_key_hex`, independent of this crate's
//!   `idempotency_key` function entirely.
//! - [`idempotency_key_matches_every_frozen_fixture_vector`] then calls the
//!   crate's actual `lore_postgres::domain::outbox::idempotency_key` against
//!   every vector, proving the shipped implementation, not just the fixture's
//!   internal consistency.
//!
//! The `negative_derivation_cases` are reproduced as discriminating collision
//! proofs (two independently-built insecure variants driven to the *same*
//! wrong hash), not single "differs from X" assertions, per the fixture's own
//! `why` text and this crate's testing-guide guidance on measuring guard
//! strength rather than asserting it.
//!
//! # `aggregate_version` v1 width pin
//!
//! `version::validate_encoded`/`AggregateVersion` are pure (no Postgres) and
//! proven directly. `append()`'s wiring of that pure check, plus the schema's
//! own wider 256-byte CHECK as a backstop for a writer that bypasses `append`
//! entirely, needs a live `Transaction` and is `#[ignore]`d below. It lives
//! here rather than in `domain_outbox_relay.rs` because it is an encoding
//! concern, not a relay one, and needs no `relay.rs` dependency.
//!
//! # `event_kind`/`aggregate_kind`/`aggregate_id` contract widths
//!
//! Also proven live here for the same reason: `MAX_EVENT_KIND_BYTES` and
//! `MAX_AGGREGATE_KIND_BYTES` have no schema CHECK backstop at all (the base
//! `CREATE TABLE` declares both columns as bare `text`), so `append()`'s
//! `validate()` is the *only* place these two contract widths are enforced.

#[path = "common/case_namespace.rs"]
mod case_namespace;

use std::path::PathBuf;

use case_namespace::CaseNamespace;
use lore_postgres::domain::outbox::OUTBOX_SCHEMA;
use lore_postgres::domain::outbox::OutboxEvent;
use lore_postgres::domain::outbox::append;
use lore_postgres::domain::outbox::append::MAX_AGGREGATE_ID_BYTES;
use lore_postgres::domain::outbox::idempotency_key;
use lore_postgres::domain::outbox::schema::IDEMPOTENCY_KEY_DOMAIN_V1;
use lore_postgres::domain::outbox::schema::MAX_AGGREGATE_KIND_BYTES;
use lore_postgres::domain::outbox::schema::MAX_EVENT_KIND_BYTES;
use lore_postgres::domain::outbox::version::AggregateVersion;
use lore_postgres::domain::outbox::version::MAX_ENCODED_AGGREGATE_VERSION_BYTES;
use lore_postgres::domain::outbox::version::MIN_AGGREGATE_VERSION_BYTES;
use lore_postgres::domain::outbox::version::validate_encoded;
use lore_postgres::pool::TlsConfig;
use serde_json::Value;
use tokio_postgres::error::SqlState;

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

/// Path to the idempotency-key fixture, relative to this crate's manifest
/// directory. `lore-postgres` and `lorehub` are sibling checkouts under the
/// `lorehub-all` container: `lore/lore-postgres/../.. == lorehub-all`.
fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../lorehub/docs/contracts/fixtures/lore-notification-plane/idempotency-key.json")
}

/// Load and parse the fixture. Panics (a genuine test failure, never a
/// silent skip) when the file is absent or malformed, per the WP-119 Step A
/// brief: the fixture is a hard dependency of this conformance suite, not an
/// optional one.
fn load_fixture() -> Value {
    let path = fixture_path();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "idempotency-key.json fixture is required and must not be skipped when absent \
             (WP-119 Step A brief: \"FAIL if absent, never skip\"). Expected it at {}: {error}",
            path.display()
        )
    });
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("idempotency-key.json is not valid JSON: {error}"))
}

fn decode_hex(label: &str, s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|error| panic!("fixture field {label} is not valid hex: {error}"))
}

/// One `vectors[]` entry, decoded into the shapes `OutboxEvent` and the
/// manual preimage builders below both need.
struct VectorInputs {
    id: String,
    cell_id: String,
    event_kind: String,
    repository_id: Vec<u8>,
    repository_generation: i64,
    aggregate_kind: String,
    aggregate_id: Vec<u8>,
    aggregate_version: Vec<u8>,
    preimage_hex: String,
    idempotency_key: [u8; 32],
}

fn parse_vector(v: &Value) -> VectorInputs {
    let id = v["id"].as_str().expect("vector id").to_owned();
    let inputs = &v["inputs"];
    let repository_generation: i64 = inputs["repository_generation"]
        .as_str()
        .unwrap_or_else(|| panic!("vector {id}: inputs.repository_generation must be a string"))
        .parse()
        .unwrap_or_else(|error| panic!("vector {id}: repository_generation not an i64: {error}"));
    let key_hex = v["idempotency_key_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("vector {id}: missing idempotency_key_hex"));
    let key_bytes = decode_hex("idempotency_key_hex", key_hex);
    let idempotency_key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("vector {id}: idempotency_key_hex is not 32 bytes"));

    VectorInputs {
        cell_id: inputs["cell_id"].as_str().expect("cell_id").to_owned(),
        event_kind: inputs["event_kind"]
            .as_str()
            .expect("event_kind")
            .to_owned(),
        repository_id: decode_hex("repository_hex", inputs["repository_hex"].as_str().unwrap()),
        repository_generation,
        aggregate_kind: inputs["aggregate_kind"]
            .as_str()
            .expect("aggregate_kind")
            .to_owned(),
        aggregate_id: decode_hex(
            "aggregate_id_hex",
            inputs["aggregate_id_hex"].as_str().unwrap(),
        ),
        aggregate_version: decode_hex(
            "aggregate_version_hex",
            inputs["aggregate_version_hex"].as_str().unwrap(),
        ),
        preimage_hex: v["preimage_hex"].as_str().expect("preimage_hex").to_owned(),
        idempotency_key,
        id,
    }
}

fn vectors(fixture: &Value) -> Vec<VectorInputs> {
    fixture["vectors"]
        .as_array()
        .expect("fixture.vectors must be an array")
        .iter()
        .map(parse_vector)
        .collect()
}

fn find<'a>(vs: &'a [VectorInputs], id: &str) -> &'a VectorInputs {
    vs.iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("fixture is missing the {id} vector this test depends on"))
}

fn as_event<'a>(v: &'a VectorInputs, payload: &'a [u8]) -> OutboxEvent<'a> {
    OutboxEvent {
        cell_id: &v.cell_id,
        repository_id: &v.repository_id,
        repository_generation: v.repository_generation,
        event_kind: &v.event_kind,
        aggregate_kind: &v.aggregate_kind,
        aggregate_id: &v.aggregate_id,
        aggregate_version: &v.aggregate_version,
        payload_schema_version: 1,
        payload,
    }
}

/// The standard (correct) field encoding: an 8-byte big-endian length prefix
/// then the field bytes, per the fixture's `algorithm.field_encoding`.
fn push_field_8(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

// ---------------------------------------------------------------------------
// Positive conformance
// ---------------------------------------------------------------------------

/// Independent of `lore_postgres::domain::outbox::idempotency_key` entirely:
/// rebuild `branch-pushed`'s preimage by hand from the fixture's own written
/// algorithm description, and check it against the fixture's *own*
/// `preimage_hex`/`idempotency_key_hex` -- proving the fixture is internally
/// self-consistent before trusting it as an oracle for the crate function.
#[test]
fn idempotency_key_manual_preimage_matches_the_fixtures_own_preimage_hex() {
    let fixture = load_fixture();
    let vs = vectors(&fixture);
    let v = find(&vs, "branch-pushed");

    let mut preimage = Vec::new();
    preimage.extend_from_slice(IDEMPOTENCY_KEY_DOMAIN_V1); // not length-prefixed
    push_field_8(&mut preimage, v.cell_id.as_bytes());
    push_field_8(&mut preimage, v.event_kind.as_bytes());
    push_field_8(&mut preimage, &v.repository_id);
    push_field_8(&mut preimage, &v.repository_generation.to_be_bytes());
    push_field_8(&mut preimage, v.aggregate_kind.as_bytes());
    push_field_8(&mut preimage, &v.aggregate_id);
    push_field_8(&mut preimage, &v.aggregate_version);

    assert_eq!(
        hex::encode(&preimage),
        v.preimage_hex,
        "manually built preimage must match the fixture's own preimage_hex for {}",
        v.id
    );
    assert_eq!(
        *blake3::hash(&preimage).as_bytes(),
        v.idempotency_key,
        "hashing the fixture's own preimage must reproduce its own idempotency_key_hex for {}",
        v.id
    );
}

/// The actual conformance proof: every fixture vector run through this
/// crate's shipped `idempotency_key` must reproduce the pinned key exactly.
#[test]
fn idempotency_key_matches_every_frozen_fixture_vector() {
    let fixture = load_fixture();
    for v in vectors(&fixture) {
        let event = as_event(&v, b"{}");
        assert_eq!(
            idempotency_key(&event),
            v.idempotency_key,
            "idempotency_key() must match the frozen fixture vector {}",
            v.id
        );
    }
}

/// `contract_pins.domain_prefix_ascii`: the fixture's stated domain prefix
/// plus its terminator byte must equal the crate's actual constant, so a
/// prefix drift between fixture and shipped code is caught here rather than
/// only inside a byte-identical hash comparison that would just look like an
/// unrelated hash mismatch.
#[test]
fn domain_prefix_constant_matches_the_fixtures_contract_pin() {
    let fixture = load_fixture();
    let ascii = fixture["contract_pins"]["domain_prefix_ascii"]["value"]
        .as_str()
        .expect("contract_pins.domain_prefix_ascii.value");
    let mut expected = ascii.as_bytes().to_vec();
    expected.push(0x00); // domain_prefix_terminator_byte
    assert_eq!(IDEMPOTENCY_KEY_DOMAIN_V1, expected.as_slice());
}

/// `negative_derivation_cases[payload-is-not-an-input]`: two exact retries
/// that rebuild different payload bytes must find the same row, because
/// `payload` is deliberately excluded from the preimage.
#[test]
fn idempotency_key_excludes_payload_bytes() {
    let fixture = load_fixture();
    let vs = vectors(&fixture);
    let v = find(&vs, "branch-pushed");

    let a = idempotency_key(&as_event(v, b"{\"r\":1}"));
    let b = idempotency_key(&as_event(v, b"{ \"r\": 1 }"));
    assert_eq!(a, b, "payload bytes must not affect the idempotency key");
    assert_eq!(a, v.idempotency_key);
}

// ---------------------------------------------------------------------------
// Negative derivation cases: discriminating collision proofs, not bare
// "differs from" assertions -- each insecure variant is built independently
// for two distinct vectors and shown to land on the SAME wrong hash, which is
// the actual vulnerability the fixture's `why` text describes.
// ---------------------------------------------------------------------------

/// `five-field-tuple-collides`: an implementation that drops
/// `repository_generation` and `aggregate_kind` produces the identical key
/// for `branch-pushed` and `branch-pushed-next-generation`, which are two
/// distinct committed mutations (they differ only in `repository_generation`,
/// the field being dropped).
#[test]
fn five_field_preimage_collides_branch_pushed_with_its_next_generation() {
    let fixture = load_fixture();
    let vs = vectors(&fixture);
    let a = find(&vs, "branch-pushed");
    let b = find(&vs, "branch-pushed-next-generation");
    assert_ne!(
        a.repository_generation, b.repository_generation,
        "the two vectors must actually differ in the field being dropped, or this proves nothing"
    );

    let five_field = |v: &VectorInputs| -> [u8; 32] {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(IDEMPOTENCY_KEY_DOMAIN_V1);
        push_field_8(&mut preimage, v.cell_id.as_bytes());
        push_field_8(&mut preimage, v.event_kind.as_bytes());
        push_field_8(&mut preimage, &v.repository_id);
        // repository_generation and aggregate_kind deliberately omitted.
        push_field_8(&mut preimage, &v.aggregate_id);
        push_field_8(&mut preimage, &v.aggregate_version);
        *blake3::hash(&preimage).as_bytes()
    };

    let hash_a = five_field(a);
    let hash_b = five_field(b);
    assert_eq!(
        hash_a, hash_b,
        "dropping repository_generation and aggregate_kind must collide these two distinct mutations"
    );
    assert_ne!(
        hash_a, a.idempotency_key,
        "the insecure five-field hash must not equal the real seven-field key"
    );
    assert_ne!(hash_a, b.idempotency_key);
}

/// `unprefixed-fields-collide`: dropping the eight-byte length prefixes makes
/// `branch-pushed` (`aggregate_kind="branch"`, `aggregate_id="main"`) and
/// `boundary-shift` (`aggregate_kind="branchm"`, `aggregate_id="ain"`)
/// indistinguishable, because the concatenated bytes are identical.
#[test]
fn unprefixed_concatenation_collides_branch_pushed_with_boundary_shift() {
    let fixture = load_fixture();
    let vs = vectors(&fixture);
    let a = find(&vs, "branch-pushed");
    let b = find(&vs, "boundary-shift");
    assert_ne!(
        a.aggregate_kind, b.aggregate_kind,
        "the two vectors must actually differ in a field-boundary way, or this proves nothing"
    );

    let unprefixed = |v: &VectorInputs| -> [u8; 32] {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(IDEMPOTENCY_KEY_DOMAIN_V1);
        preimage.extend_from_slice(v.cell_id.as_bytes());
        preimage.extend_from_slice(v.event_kind.as_bytes());
        preimage.extend_from_slice(&v.repository_id);
        preimage.extend_from_slice(&v.repository_generation.to_be_bytes());
        preimage.extend_from_slice(v.aggregate_kind.as_bytes());
        preimage.extend_from_slice(&v.aggregate_id);
        preimage.extend_from_slice(&v.aggregate_version);
        *blake3::hash(&preimage).as_bytes()
    };

    let hash_a = unprefixed(a);
    let hash_b = unprefixed(b);
    assert_eq!(
        hash_a, hash_b,
        "dropping the length prefixes must collide branch-pushed with boundary-shift"
    );
    assert_ne!(hash_a, a.idempotency_key);
    assert_ne!(hash_a, b.idempotency_key);
}

/// `four-byte-length-prefix-changes-the-digest`: this derivation's 8-byte
/// length prefixes are not interchangeable with a sibling derivation's 4-byte
/// ones (`stream_reset_derivation`'s `reset_fingerprint`).
#[test]
fn four_byte_length_prefix_changes_the_digest() {
    let fixture = load_fixture();
    let vs = vectors(&fixture);
    let v = find(&vs, "branch-pushed");

    let push_field_4 = |buf: &mut Vec<u8>, field: &[u8]| {
        buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
        buf.extend_from_slice(field);
    };
    let mut preimage = Vec::new();
    preimage.extend_from_slice(IDEMPOTENCY_KEY_DOMAIN_V1);
    push_field_4(&mut preimage, v.cell_id.as_bytes());
    push_field_4(&mut preimage, v.event_kind.as_bytes());
    push_field_4(&mut preimage, &v.repository_id);
    push_field_4(&mut preimage, &v.repository_generation.to_be_bytes());
    push_field_4(&mut preimage, v.aggregate_kind.as_bytes());
    push_field_4(&mut preimage, &v.aggregate_id);
    push_field_4(&mut preimage, &v.aggregate_version);

    let hash = *blake3::hash(&preimage).as_bytes();
    assert_ne!(
        hash, v.idempotency_key,
        "an 8-byte-prefix derivation must not be reproducible with 4-byte prefixes"
    );
}

// ---------------------------------------------------------------------------
// aggregate_version v1 width, pure half: `version::validate_encoded` needs no
// Postgres connection at all, so the 7/8/128/129-byte boundary is proven here
// directly against the pure encoding module rather than only through a live
// `append()` round trip below.
// ---------------------------------------------------------------------------

#[test]
fn validate_encoded_pins_the_8_to_128_byte_boundary() {
    assert_eq!(MIN_AGGREGATE_VERSION_BYTES, 8);
    assert_eq!(MAX_ENCODED_AGGREGATE_VERSION_BYTES, 128);

    assert!(
        validate_encoded(&[0u8; 7]).is_err(),
        "7 bytes must be rejected: no room for the 8-byte ordinal"
    );
    assert!(
        validate_encoded(&[0u8; 8]).is_ok(),
        "8 bytes (ordinal only, empty identity) must be accepted"
    );
    assert!(
        validate_encoded(&[0u8; 128]).is_ok(),
        "128 bytes (ordinal plus the widest 120-byte identity) must be accepted"
    );
    assert!(
        validate_encoded(&[0u8; 129]).is_err(),
        "129 bytes must be rejected: over the frozen encoded width"
    );
}

/// The same boundary through `AggregateVersion::decode`, and a round-trip
/// proof that encoding the widest legal identity produces exactly 128 bytes
/// and decodes back losslessly -- not just that some 128-byte buffer of
/// zeros happens to pass the length check above.
#[test]
fn aggregate_version_encode_decode_round_trips_at_the_widest_legal_identity() {
    let widest_identity = vec![0x5Au8; 120];
    let version = AggregateVersion::new(u64::MAX, widest_identity.clone())
        .expect("120-byte identity is exactly at the pinned bound");
    let encoded = version.encode();
    assert_eq!(encoded.len(), 128);
    assert_eq!(AggregateVersion::decode(&encoded).expect("decode"), version);

    let one_byte_over = vec![0x5Au8; 121];
    assert!(
        AggregateVersion::new(u64::MAX, one_byte_over).is_err(),
        "a 121-byte identity (129-byte total) must be rejected by the constructor too"
    );
}

// ---------------------------------------------------------------------------
// aggregate_version v1 width pin (Postgres-backed; the one half of this file
// that cannot be pure). See the module doc for why this lives here rather
// than in domain_outbox_relay.rs, and why it is currently expected to FAIL.
// ---------------------------------------------------------------------------

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

async fn connect_domain_store(url: &str) -> lore_postgres::domain::PostgresDomainStore {
    lore_postgres::domain::PostgresDomainStore::connect(url, 2, &TlsConfig::default())
        .await
        .expect("connect domain store")
}

async fn pg_client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test setup");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

fn versioned_event<'a>(
    cell_id: &'a str,
    repository_id: &'a [u8],
    aggregate_id: &'a [u8],
    aggregate_version: &'a [u8],
) -> OutboxEvent<'a> {
    OutboxEvent {
        cell_id,
        repository_id,
        repository_generation: 1,
        event_kind: "branch.pushed",
        aggregate_kind: "branch",
        aggregate_id,
        aggregate_version,
        payload_schema_version: 1,
        payload: b"{}",
    }
}

/// CR-032 F-032-4: `aggregate_version` is an 8-byte big-endian u64 ordinal
/// plus 0..=120 identity bytes, so its total width is 8..=128 bytes. `append`
/// must reject 7 and 129 bytes and accept 8 and 128, both through its own
/// pre-SQL `validate()` and through the schema's own CHECK constraint as a
/// backstop for any writer that bypasses `append`.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn aggregate_version_v1_width_is_8_to_128_bytes_inclusive() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping aggregate_version width test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;

    for (label, len, must_be_accepted) in [
        ("7 bytes (below minimum)", 7usize, false),
        ("8 bytes (minimum)", 8usize, true),
        ("128 bytes (maximum)", 128usize, true),
        ("129 bytes (above maximum)", 129usize, false),
    ] {
        let repository_id: [u8; 16] = rand::random();
        let cell_id = format!("cell-{:016x}", rand::random::<u64>());
        let aggregate_id: [u8; 16] = rand::random();
        let version = vec![0xABu8; len];

        let tx = client
            .transaction()
            .await
            .unwrap_or_else(|e| panic!("begin tx for {label}: {e}"));
        let event = versioned_event(&cell_id, &repository_id, &aggregate_id, &version);
        let result = append(&tx, &event).await;

        if must_be_accepted {
            result.unwrap_or_else(|e| panic!("{label} must be accepted by append(): {e:?}"));
            tx.commit()
                .await
                .unwrap_or_else(|e| panic!("commit accepted append for {label}: {e}"));
        } else {
            let err = result.expect_err(&format!("{label} must be rejected by append()"));
            assert!(
                matches!(err, lore_postgres::domain::DomainError::InvalidInput(_)),
                "{label}: expected InvalidInput, got {err:?}"
            );
            tx.rollback()
                .await
                .unwrap_or_else(|e| panic!("rollback rejected append for {label}: {e}"));
        }
    }

    // The column CHECK is a DELIBERATE superset of the v1 bound (schema.rs's
    // own doc comment on `MAX_AGGREGATE_VERSION_BYTES`: "the column keeps the
    // wider CHECK so the narrowing is a Rust-side contract rather than a type
    // change on a table"). So a raw INSERT that bypasses `append` entirely
    // must SUCCEED at 7 and 129 bytes (both inside the wider 256-byte CHECK,
    // both outside the v1 encoding `append` enforces) -- proving the v1 bound
    // has no schema-level backstop, rather than assuming one exists. The
    // schema's own actual boundary is 256 vs 257 bytes.
    for (label, len) in [
        ("7 bytes", 7usize),
        ("129 bytes", 129usize),
        ("256 bytes", 256usize),
    ] {
        let repository_id: [u8; 16] = rand::random();
        let cell_id = format!("cell-{:016x}", rand::random::<u64>());
        let aggregate_id: [u8; 16] = rand::random();
        let version = vec![0xCDu8; len];

        let tx = client
            .transaction()
            .await
            .unwrap_or_else(|e| panic!("begin raw-insert tx for {label}: {e}"));
        tx.execute(
            "INSERT INTO lore_outbox_events (
                event_id, cell_id, idempotency_key, repository_id, repository_generation,
                event_kind, aggregate_kind, aggregate_id, aggregate_version,
                payload_schema_version, payload, state, created_at, available_at
            ) VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}',
                      'pending', clock_timestamp(), clock_timestamp())",
            &[
                &uuid::Uuid::new_v4(),
                &cell_id,
                &rand::random::<[u8; 32]>().as_slice(),
                &repository_id.as_slice(),
                &aggregate_id.as_slice(),
                &version.as_slice(),
            ],
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "raw insert with aggregate_version of {label} must be ACCEPTED by the wider \
                 schema CHECK (only append()'s Rust-side validate() enforces 8..=128): {e}"
            )
        });
        tx.rollback()
            .await
            .unwrap_or_else(|e| panic!("rollback raw-insert tx for {label}: {e}"));
    }

    // The schema CHECK's own actual boundary: 257 bytes must be rejected.
    let repository_id: [u8; 16] = rand::random();
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id: [u8; 16] = rand::random();
    let version = vec![0xCDu8; 257];
    let tx = client
        .transaction()
        .await
        .expect("begin raw-insert tx for 257 bytes");
    let raw_err = tx
        .execute(
            "INSERT INTO lore_outbox_events (
                event_id, cell_id, idempotency_key, repository_id, repository_generation,
                event_kind, aggregate_kind, aggregate_id, aggregate_version,
                payload_schema_version, payload, state, created_at, available_at
            ) VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, $6, 1, '{}',
                      'pending', clock_timestamp(), clock_timestamp())",
            &[
                &uuid::Uuid::new_v4(),
                &cell_id,
                &rand::random::<[u8; 32]>().as_slice(),
                &repository_id.as_slice(),
                &aggregate_id.as_slice(),
                &version.as_slice(),
            ],
        )
        .await
        .expect_err("257 bytes must be rejected by the schema's own 256-byte CHECK");
    let db_err = raw_err.as_db_error().expect("expected a database error");
    assert_eq!(db_err.code(), &SqlState::CHECK_VIOLATION);
    tx.rollback()
        .await
        .expect("rollback raw-insert tx for 257 bytes");
}

/// The notification-plane contract's `event_kind`/`aggregate_kind` widths (64
/// UTF-8 bytes each) and the base schema's `aggregate_id` width (64 bytes)
/// through a live `append()`. `event_kind`/`aggregate_kind` have no schema
/// CHECK at all, so `validate()` is their only backstop -- there is no raw-
/// insert half to prove here the way there is for `aggregate_version`.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn event_kind_aggregate_kind_and_aggregate_id_are_rejected_over_their_pinned_widths() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping kind/id width test");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let ordinal_only_version = AggregateVersion::ordinal_only(1).encode();

    async fn try_append(
        client: &mut tokio_postgres::Client,
        event: &OutboxEvent<'_>,
    ) -> Result<(), lore_postgres::domain::DomainError> {
        let tx = client.transaction().await.expect("begin tx");
        let result = append(&tx, event).await;
        if result.is_ok() {
            tx.commit().await.expect("commit accepted append");
        } else {
            tx.rollback().await.expect("rollback rejected append");
        }
        result.map(|_| ())
    }

    // event_kind: at-cap accepted, one over rejected.
    let repository_id: [u8; 16] = rand::random();
    let at_cap_kind = "k".repeat(MAX_EVENT_KIND_BYTES);
    let over_cap_kind = "k".repeat(MAX_EVENT_KIND_BYTES + 1);
    let cell_a = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id_a: [u8; 16] = rand::random();
    let mut event = versioned_event(
        &cell_a,
        &repository_id,
        &aggregate_id_a,
        &ordinal_only_version,
    );
    event.event_kind = &at_cap_kind;
    try_append(&mut client, &event)
        .await
        .expect("event_kind at the pinned cap must be accepted");
    let cell_b = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id_b: [u8; 16] = rand::random();
    let mut event = versioned_event(
        &cell_b,
        &repository_id,
        &aggregate_id_b,
        &ordinal_only_version,
    );
    event.event_kind = &over_cap_kind;
    let err = try_append(&mut client, &event)
        .await
        .expect_err("event_kind one byte over the pinned cap must be rejected");
    assert!(matches!(
        err,
        lore_postgres::domain::DomainError::InvalidInput(_)
    ));

    // aggregate_kind: at-cap accepted, one over rejected.
    let at_cap_kind = "k".repeat(MAX_AGGREGATE_KIND_BYTES);
    let over_cap_kind = "k".repeat(MAX_AGGREGATE_KIND_BYTES + 1);
    let cell_c = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id_c: [u8; 16] = rand::random();
    let mut event = versioned_event(
        &cell_c,
        &repository_id,
        &aggregate_id_c,
        &ordinal_only_version,
    );
    event.aggregate_kind = &at_cap_kind;
    try_append(&mut client, &event)
        .await
        .expect("aggregate_kind at the pinned cap must be accepted");
    let cell_d = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id_d: [u8; 16] = rand::random();
    let mut event = versioned_event(
        &cell_d,
        &repository_id,
        &aggregate_id_d,
        &ordinal_only_version,
    );
    event.aggregate_kind = &over_cap_kind;
    let err = try_append(&mut client, &event)
        .await
        .expect_err("aggregate_kind one byte over the pinned cap must be rejected");
    assert!(matches!(
        err,
        lore_postgres::domain::DomainError::InvalidInput(_)
    ));

    // aggregate_id: at-cap accepted, one over rejected (backed by the schema
    // CHECK too, but that half is already covered by the existing
    // domain_outbox.rs payload-bound test's sibling pattern; this proves the
    // append()-level pre-check).
    let cell_e = format!("cell-{:016x}", rand::random::<u64>());
    let at_cap_id = vec![7u8; MAX_AGGREGATE_ID_BYTES];
    let event = versioned_event(&cell_e, &repository_id, &at_cap_id, &ordinal_only_version);
    try_append(&mut client, &event)
        .await
        .expect("aggregate_id at the pinned cap must be accepted");
    let cell_f = format!("cell-{:016x}", rand::random::<u64>());
    let over_cap_id = vec![7u8; MAX_AGGREGATE_ID_BYTES + 1];
    let event = versioned_event(&cell_f, &repository_id, &over_cap_id, &ordinal_only_version);
    let err = try_append(&mut client, &event)
        .await
        .expect_err("aggregate_id one byte over the pinned cap must be rejected");
    assert!(matches!(
        err,
        lore_postgres::domain::DomainError::InvalidInput(_)
    ));
}

// ---------------------------------------------------------------------------
// A database bootstrapped from the OLD (pre-`SCHEMA-119`) base schema
// upgrades in place, keeping an existing pending row intact (behavior 8).
// ---------------------------------------------------------------------------

/// Extract `pub const OUTBOX_SCHEMA: &str = r#"..."#;`'s raw-string body from
/// a historical `schema.rs` blob, via `git show <sha>:<path>` rather than a
/// checked-in copy -- the ground truth for "what WP-116 actually shipped" is
/// the git history, not a second hand-maintained source string that could
/// itself drift from it.
fn old_outbox_schema_ddl_at(git_sha: &str) -> String {
    let output = std::process::Command::new("git")
        .args([
            "show",
            &format!("{git_sha}:lore-postgres/src/domain/outbox/schema.rs"),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap_or_else(|error| panic!("run `git show {git_sha}:...schema.rs`: {error}"));
    assert!(
        output.status.success(),
        "git show {git_sha}:...schema.rs failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("git blob is UTF-8");
    let start_marker = "pub const OUTBOX_SCHEMA: &str = r#\"";
    let start = text
        .find(start_marker)
        .unwrap_or_else(|| panic!("could not find {start_marker:?} in {git_sha}:...schema.rs"))
        + start_marker.len();
    let end = text[start..].find("\"#;").unwrap_or_else(|| {
        panic!("could not find the closing r#\"...\"# in {git_sha}:...schema.rs")
    }) + start;
    text[start..end].to_owned()
}

/// A cell bootstrapped before `SCHEMA-119` (this Lore fork's `bb00d3b`, WP-116's
/// landed `OUTBOX-BASE-API-READY` base) must upgrade in place when it boots
/// the current binary: no error, and an existing `pending` row survives with
/// its identity untouched. This is the live half of behavior 8 that the
/// existing `domain_migration_parity`/`domain_store_connect_is_idempotent_*`
/// tests do not cover -- those prove the CURRENT schema is self-consistent
/// and idempotent, not that it upgrades cleanly FROM the prior shipped shape.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_database_bootstrapped_from_the_old_base_schema_upgrades_in_place_and_keeps_a_pending_row()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "old-schema-up").await;
    let url = namespace.pg_url().to_owned();

    // 1. Apply the OLD (pre-SCHEMA-119) base schema directly -- simulating a
    // cell that was bootstrapped by the WP-116 binary and never upgraded.
    let old_ddl = old_outbox_schema_ddl_at("bb00d3b");
    let (old_client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect to apply the old schema");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("old-schema connection error: {e}");
        }
    });
    old_client
        .batch_execute(&old_ddl)
        .await
        .expect("apply the old (pre-SCHEMA-119) base schema");

    // 2. Insert one pending row using the OLD 14-column shape (no relay
    // columns exist yet), matching what a live WP-116-only cell would hold.
    let event_id = uuid::Uuid::new_v4();
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    let repository_id: [u8; 16] = rand::random();
    let aggregate_id: [u8; 16] = rand::random();
    let idempotency_key: [u8; 32] = rand::random();
    old_client
        .execute(
            "INSERT INTO lore_outbox_events (
                event_id, cell_id, idempotency_key, repository_id, repository_generation,
                event_kind, aggregate_kind, aggregate_id, aggregate_version,
                payload_schema_version, payload, state, created_at, available_at
            ) VALUES ($1, $2, $3, $4, 1, 'branch.pushed', 'branch', $5, 'v1', 1, '{}',
                      'pending', clock_timestamp(), clock_timestamp())",
            &[
                &event_id,
                &cell_id,
                &idempotency_key.as_slice(),
                &repository_id.as_slice(),
                &aggregate_id.as_slice(),
            ],
        )
        .await
        .expect("seed a pending row under the old schema");
    // The old schema also seeds its own `lore_outbox_schema_state` singleton
    // (its DDL creates the table but nothing inserts into it -- WP-116's own
    // runtime code does that, not the DDL constant); nothing here depends on
    // that row, only on `lore_outbox_events`.

    // 3. Boot the CURRENT binary's runtime schema against the SAME database.
    // This is the real upgrade path: `ensure_schema` applies `OUTBOX_SCHEMA`
    // (now including the SCHEMA-119 `ALTER TABLE ADD COLUMN IF NOT EXISTS`
    // block) under the shared advisory lock.
    let pool = lore_postgres::pool::build_pool(&url, 2, &TlsConfig::default())
        .expect("build pool for upgrade");
    lore_postgres::pool::ensure_schema(&pool, OUTBOX_SCHEMA)
        .await
        .expect("the current schema must apply cleanly over the old base schema");

    // 4. The pre-existing row must be untouched: identity intact, still
    // pending, and the new relay columns are NULL (satisfying the new
    // `lore_outbox_events_publication_shape` CHECK for a `pending` row).
    let row = old_client
        .query_one(
            "SELECT cell_id, idempotency_key, repository_id, aggregate_id, state, \
                    claim_generation, claim_owner, stream_identity \
             FROM lore_outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .await
        .expect("the pre-existing row must survive the upgrade");
    let row_cell_id: String = row.get("cell_id");
    let row_key: Vec<u8> = row.get("idempotency_key");
    let row_repository_id: Vec<u8> = row.get("repository_id");
    let row_aggregate_id: Vec<u8> = row.get("aggregate_id");
    let row_state: String = row.get("state");
    let row_claim_generation: i64 = row.get("claim_generation");
    let row_claim_owner: Option<String> = row.get("claim_owner");
    let row_stream_identity: Option<String> = row.get("stream_identity");

    assert_eq!(row_cell_id, cell_id);
    assert_eq!(row_key, idempotency_key.to_vec());
    assert_eq!(row_repository_id, repository_id.to_vec());
    assert_eq!(row_aggregate_id, aggregate_id.to_vec());
    assert_eq!(row_state, "pending");
    assert_eq!(
        row_claim_generation, 0,
        "the new claim_generation column must default to 0 for a pre-existing row"
    );
    assert!(row_claim_owner.is_none());
    assert!(row_stream_identity.is_none());

    // Applying it a SECOND time (a second replica booting, or a restart)
    // must also be a no-op -- the general idempotence claim, specifically
    // exercised against the just-upgraded database rather than a fresh one.
    lore_postgres::pool::ensure_schema(&pool, OUTBOX_SCHEMA)
        .await
        .expect("re-applying the current schema after upgrade must stay idempotent");

    namespace.release().await;
}

/// Regression for a fix-round defect: the six dead-letter redelivery columns
/// and their two constraints originally lived inside
/// `lore_outbox_dead_letters`'s `CREATE TABLE IF NOT EXISTS` body, which
/// never reaches a database where the table already exists -- so a cell that
/// bootstrapped before that fix landed would keep missing them forever,
/// `dead_letter` failing with "column does not exist" rather than returning
/// a typed outcome. The fix moved them to `ALTER TABLE ... ADD COLUMN IF NOT
/// EXISTS` plus a `DO` block. This proves the ALTER path actually recovers a
/// database that is missing them, which `domain_migration_parity` and the
/// idempotent-double-apply test above structurally cannot: both of those
/// compare two FRESH installs, and a fresh install never exercises the
/// already-exists-without-these-columns case at all.
///
/// Revert-check: this fails against the pre-fix `CREATE TABLE IF NOT EXISTS`
/// declaration, because that DDL is a no-op on a table that already exists,
/// so the dropped columns/constraints would never come back.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn dead_letter_columns_and_constraints_dropped_from_an_existing_table_are_restored_by_reapplying_the_schema()
 {
    let Some(base_url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    let namespace = CaseNamespace::acquire(&base_url, "dl-cols-restore").await;
    let url = namespace.pg_url().to_owned();

    // 1. A normal current-schema boot.
    connect_domain_store(&url).await;

    // 2. Simulate a database that was bootstrapped by a build predating the
    // fix: drop the two constraints (must go first; they reference the
    // columns) and then the six columns.
    let (admin_client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect to damage the schema");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("dead-letter-columns-restore connection error: {e}");
        }
    });
    admin_client
        .batch_execute(
            "ALTER TABLE lore_outbox_dead_letters \
                 DROP CONSTRAINT IF EXISTS lore_outbox_dead_letters_previous_disposition_shape, \
                 DROP CONSTRAINT IF EXISTS lore_outbox_dead_letters_redelivery_shape; \
             ALTER TABLE lore_outbox_dead_letters \
                 DROP COLUMN IF EXISTS claim_generation, \
                 DROP COLUMN IF EXISTS dead_letter_count, \
                 DROP COLUMN IF EXISTS previous_disposition, \
                 DROP COLUMN IF EXISTS previous_disposition_reason, \
                 DROP COLUMN IF EXISTS previous_disposition_at, \
                 DROP COLUMN IF EXISTS previous_disposition_actor;",
        )
        .await
        .expect("drop the dead-letter redelivery columns and constraints");

    // `information_schema.columns` is database-wide, not schema-scoped by
    // `search_path`, so every query against it below explicitly filters on
    // this namespace's own schema -- unscoped, it would count the SAME six
    // columns from every OTHER live case's own `lore_outbox_dead_letters`
    // table sharing this database and always read back 6 regardless of what
    // this case actually dropped.
    let schema_name = namespace.schema_name().to_owned();
    let missing_columns_before: i64 = admin_client
        .query_one(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = $2 \
               AND table_name = 'lore_outbox_dead_letters' \
               AND column_name = ANY($1)",
            &[
                &vec![
                    "claim_generation",
                    "dead_letter_count",
                    "previous_disposition",
                    "previous_disposition_reason",
                    "previous_disposition_at",
                    "previous_disposition_actor",
                ],
                &schema_name,
            ],
        )
        .await
        .expect("count columns before reapply")
        .get(0);
    assert_eq!(
        missing_columns_before, 0,
        "the drop must have actually removed all six columns, or this test proves nothing"
    );

    // 3. Re-apply the CURRENT schema (the fixed ALTER TABLE ADD COLUMN IF NOT
    // EXISTS path) against this damaged, already-existing database.
    let pool = lore_postgres::pool::build_pool(&url, 2, &TlsConfig::default())
        .expect("build pool for schema restore");
    lore_postgres::pool::ensure_schema(&pool, OUTBOX_SCHEMA)
        .await
        .expect("reapplying the schema must restore the dropped columns and constraints");

    // 4. All six columns and both constraints must be back.
    let restored_columns: i64 = admin_client
        .query_one(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = $2 \
               AND table_name = 'lore_outbox_dead_letters' \
               AND column_name = ANY($1)",
            &[
                &vec![
                    "claim_generation",
                    "dead_letter_count",
                    "previous_disposition",
                    "previous_disposition_reason",
                    "previous_disposition_at",
                    "previous_disposition_actor",
                ],
                &schema_name,
            ],
        )
        .await
        .expect("count columns after reapply")
        .get(0);
    assert_eq!(
        restored_columns, 6,
        "all six dropped columns must be restored"
    );

    let restored_constraints: i64 = admin_client
        .query_one(
            "SELECT count(*) FROM pg_constraint \
             WHERE conrelid = 'lore_outbox_dead_letters'::regclass \
               AND conname = ANY($1)",
            &[&vec![
                "lore_outbox_dead_letters_previous_disposition_shape",
                "lore_outbox_dead_letters_redelivery_shape",
            ]],
        )
        .await
        .expect("count constraints after reapply")
        .get(0);
    assert_eq!(
        restored_constraints, 2,
        "both dropped constraints must be restored"
    );

    // 5. The restored table must actually be usable end to end: a real
    // dead-letter write must succeed, not merely "the columns exist".
    let mut raw = pg_client(&url).await;
    let mut pool_client = pool
        .get()
        .await
        .expect("checkout pool client for dead_letter");
    let repository_id: [u8; 16] = rand::random();
    let cell_id = format!("cell-{:016x}", rand::random::<u64>());
    let aggregate_id: [u8; 16] = rand::random();
    let version = AggregateVersion::ordinal_only(1).encode();
    let tx = raw.transaction().await.expect("begin append tx");
    let event = OutboxEvent {
        cell_id: &cell_id,
        repository_id: &repository_id,
        repository_generation: 1,
        event_kind: "branch.pushed",
        aggregate_kind: "branch",
        aggregate_id: &aggregate_id,
        aggregate_version: &version,
        payload_schema_version: 1,
        payload: b"{}",
    };
    let appended = append(&tx, &event).await.expect("append pending event");
    tx.commit().await.expect("commit append");

    let outcome = lore_postgres::domain::outbox::relay::claim_batch(
        &mut pool_client,
        "worker-restore-check",
        1,
        std::time::Duration::from_secs(30),
    )
    .await
    .expect("claim the row");
    let claim_generation = outcome[0].claim_generation;
    let dead_letter_outcome = lore_postgres::domain::outbox::relay::dead_letter(
        &mut pool_client,
        appended.event_id,
        claim_generation,
        "RESTORE_CHECK_V1",
    )
    .await
    .expect("dead_letter must succeed against the restored table, not error on a missing column");
    assert_eq!(
        dead_letter_outcome,
        lore_postgres::domain::outbox::relay::CasOutcome::Applied
    );

    namespace.release().await;
}

// ---------------------------------------------------------------------------
// aggregate-version.json conformance (F-032-4 / PIN-2). Non-ignored, pure:
// `AggregateVersion::decode`/`validate_encoded` need no Postgres connection.
// ---------------------------------------------------------------------------

struct VersionVector {
    id: String,
    bytes: Vec<u8>,
    expected_valid: bool,
    expected_ordinal: Option<u64>,
    expected_identity: Option<Vec<u8>>,
}

fn parse_version_vector(v: &Value) -> VersionVector {
    let id = v["id"].as_str().expect("vector id").to_owned();
    let bytes = decode_hex("bytes_hex", v["bytes_hex"].as_str().unwrap_or(""));
    let byte_length = v["byte_length"].as_u64().expect("byte_length") as usize;
    assert_eq!(
        bytes.len(),
        byte_length,
        "vector {id}: bytes_hex length must match byte_length"
    );
    let expected_valid = v["expected_valid"].as_bool().expect("expected_valid");
    let expected_ordinal = v["expected_ordinal"].as_str().map(|s| {
        s.parse::<u64>()
            .unwrap_or_else(|e| panic!("vector {id}: expected_ordinal not a u64: {e}"))
    });
    let expected_identity = v["expected_identity_hex"]
        .as_str()
        .map(|s| decode_hex("expected_identity_hex", s));
    VersionVector {
        id,
        bytes,
        expected_valid,
        expected_ordinal,
        expected_identity,
    }
}

#[test]
fn aggregate_version_fixture_vectors_match_decode_and_validate_encoded() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../lorehub/docs/contracts/fixtures/lore-notification-plane/aggregate-version.json",
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "aggregate-version.json fixture is required and must not be skipped when absent: {} ({e})",
            path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&text).expect("valid JSON");

    // Cross-check the fixture's stated widths against the crate's own
    // constants rather than trusting the fixture in isolation.
    assert_eq!(
        fixture["layout"]["total_byte_length_min"].as_u64(),
        Some(MIN_AGGREGATE_VERSION_BYTES as u64)
    );
    assert_eq!(
        fixture["layout"]["total_byte_length_max"].as_u64(),
        Some(MAX_ENCODED_AGGREGATE_VERSION_BYTES as u64)
    );

    for v in fixture["vectors"].as_array().expect("vectors array") {
        let vector = parse_version_vector(v);

        // Both entry points must agree: the pure width check and the actual
        // decoder.
        assert_eq!(
            validate_encoded(&vector.bytes).is_ok(),
            vector.expected_valid,
            "vector {}: validate_encoded disagreement",
            vector.id
        );
        let decoded = AggregateVersion::decode(&vector.bytes);
        assert_eq!(
            decoded.is_ok(),
            vector.expected_valid,
            "vector {}: decode disagreement",
            vector.id
        );
        if let Ok(decoded) = decoded {
            if let Some(expected_ordinal) = vector.expected_ordinal {
                assert_eq!(
                    decoded.ordinal, expected_ordinal,
                    "vector {}: ordinal",
                    vector.id
                );
            }
            if let Some(expected_identity) = &vector.expected_identity {
                assert_eq!(
                    &decoded.identity, expected_identity,
                    "vector {}: identity",
                    vector.id
                );
            }
        }
    }
}

/// `ordinal_extraction_cases`: proves the ordinal, not the whole byte string,
/// is what a consumer compares.
#[test]
fn aggregate_version_ordinal_extraction_cases() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../lorehub/docs/contracts/fixtures/lore-notification-plane/aggregate-version.json",
    );
    let text = std::fs::read_to_string(&path).expect("fixture present (checked above)");
    let fixture: Value = serde_json::from_str(&text).expect("valid JSON");

    let cases = fixture["ordinal_extraction_cases"]
        .as_array()
        .expect("cases array");

    let ordinal_ignores_identity = cases
        .iter()
        .find(|c| c["id"] == "ordinal-ignores-identity")
        .expect("ordinal-ignores-identity case");
    let a = decode_hex(
        "bytes_a_hex",
        ordinal_ignores_identity["bytes_a_hex"].as_str().unwrap(),
    );
    let b = decode_hex(
        "bytes_b_hex",
        ordinal_ignores_identity["bytes_b_hex"].as_str().unwrap(),
    );
    let va = AggregateVersion::decode(&a).expect("decode a");
    let vb = AggregateVersion::decode(&b).expect("decode b");
    assert_eq!(va.ordinal, vb.ordinal);
    assert_ne!(va.identity, vb.identity);

    let whole_string = cases
        .iter()
        .find(|c| c["id"] == "whole-string-comparison-invents-an-order")
        .expect("whole-string case");
    let a = decode_hex("bytes_a_hex", whole_string["bytes_a_hex"].as_str().unwrap());
    let b = decode_hex("bytes_b_hex", whole_string["bytes_b_hex"].as_str().unwrap());
    assert!(
        b > a,
        "the fixture's own premise requires raw byte comparison to rank b above a"
    );
    let va = AggregateVersion::decode(&a).expect("decode a");
    let vb = AggregateVersion::decode(&b).expect("decode b");
    assert_eq!(
        va.ordinal, vb.ordinal,
        "the fixture's own premise: same ordinal"
    );
    // FINDING (fixture prose vs. shipped implementation, reported rather than
    // silently reconciled): this vector's own `why` text calls the two values
    // "the SAME committed version... The ordinal comparison is what makes
    // them equal," suggesting `VersionOrder::Equal`. The fixture does NOT
    // actually pin an `expected_version_order` field, though, and the shipped
    // `compare_within_aggregate` (whose own doc comment reasons through this
    // exact shape) returns `Incomparable` for same-ordinal-different-identity
    // by design: two different identity bytes under one ordinal means the two
    // versions disagree about what that ordinal WAS, which is a real anomaly
    // to refetch and investigate, not a duplicate to silently treat as equal.
    // That reading is also the one consistent with CR-032's consumer table
    // ("Gap or incomparable ... | Refetch authoritative state"). Asserting
    // the fixture's literal "Equal" framing here would make this test pass
    // against a version.rs that silently discards a genuine identity
    // mismatch, which is the wrong side to be correct on.
    assert_eq!(
        va.compare_within_aggregate(&vb),
        lore_postgres::domain::outbox::VersionOrder::Incomparable,
        "same ordinal, different identity must be Incomparable (forces refetch), not silently Equal"
    );

    // "incomparable-across-aggregates": the design point (module docs on
    // `AggregateVersion`) is that the type itself carries no aggregate
    // identity and therefore CANNOT distinguish the two aggregates the
    // fixture describes -- `compare_within_aggregate` reports the same
    // ordinal Equal regardless. That is exactly why callers, not this type,
    // must establish same-aggregate scope (matching event_kind, aggregate_kind,
    // aggregate_id) before ever calling it; this test documents the boundary
    // rather than asserting behavior the type cannot have.
    let incomparable = cases
        .iter()
        .find(|c| c["id"] == "incomparable-across-aggregates")
        .expect("incomparable case");
    let shared_bytes = decode_hex("bytes_hex", incomparable["bytes_hex"].as_str().unwrap());
    let same_ordinal_twice = AggregateVersion::decode(&shared_bytes).expect("decode");
    assert_eq!(
        same_ordinal_twice.compare_within_aggregate(&same_ordinal_twice),
        lore_postgres::domain::outbox::VersionOrder::Equal,
        "the type has no aggregate-identity field to discriminate the two fixture aggregates; \
         scope enforcement is the caller's responsibility, not this type's"
    );
}

// ---------------------------------------------------------------------------
// event-kinds.json conformance (PIN-4). Non-ignored, pure. The value-set
// enumeration itself is reversible/pending sign-off and is a PRODUCER
// classification concern (which mutation maps to which event_kind), not
// something `append()` enforces -- only the two widths are append()-level
// concerns, already proven live above. This file cross-checks the fixture's
// internal consistency and the one thing that IS live-testable purely: that
// `idempotency_key` really is sensitive to the exact `event_kind` string
// (the "rename-is-a-new-payload-version" negative case).
// ---------------------------------------------------------------------------

#[test]
fn event_kinds_fixture_widths_and_counts_are_self_consistent() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../lorehub/docs/contracts/fixtures/lore-notification-plane/event-kinds.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "event-kinds.json fixture is required and must not be skipped when absent: {} ({e})",
            path.display()
        )
    });
    let fixture: Value = serde_json::from_str(&text).expect("valid JSON");

    let event_kind_max = fixture["widths"]["event_kind_max_utf8_bytes"]
        .as_u64()
        .unwrap();
    let aggregate_kind_max = fixture["widths"]["aggregate_kind_max_utf8_bytes"]
        .as_u64()
        .unwrap();
    assert_eq!(event_kind_max, MAX_EVENT_KIND_BYTES as u64);
    assert_eq!(aggregate_kind_max, MAX_AGGREGATE_KIND_BYTES as u64);

    let aggregate_kinds = fixture["aggregate_kinds"]
        .as_array()
        .expect("aggregate_kinds array");
    let mut all_event_kinds: Vec<String> = Vec::new();
    for ak in aggregate_kinds {
        let aggregate_kind = ak["aggregate_kind"].as_str().expect("aggregate_kind");
        assert!(
            aggregate_kind.len() as u64 <= aggregate_kind_max,
            "aggregate_kind {aggregate_kind:?} exceeds the pinned width"
        );
        for ek in ak["event_kinds"].as_array().expect("event_kinds array") {
            let event_kind = ek.as_str().expect("event_kind string").to_owned();
            assert!(
                event_kind.len() as u64 <= event_kind_max,
                "event_kind {event_kind:?} exceeds the pinned width"
            );
            all_event_kinds.push(event_kind);
        }
    }

    let counts_aggregate_kinds = fixture["counts"]["aggregate_kinds"].as_u64().unwrap();
    let counts_event_kinds = fixture["counts"]["event_kinds"].as_u64().unwrap();
    assert_eq!(aggregate_kinds.len() as u64, counts_aggregate_kinds);
    assert_eq!(all_event_kinds.len() as u64, counts_event_kinds);

    // The longest examples the fixture names must actually be present and
    // actually be the longest, not just individually under the cap.
    //
    // FINDING, reported rather than silently worked around: as of this
    // writing this assertion FAILS. The fixture names
    // `repository.default_branch_changed` (33 bytes) as
    // `longest_event_kind`, but `fragment.lifecycle_generation_advanced` (38
    // bytes, under `aggregate_kind: "fragment_lifecycle"`) is actually
    // longer. Both are still well inside `MAX_EVENT_KIND_BYTES` (64), so this
    // is a fixture self-consistency defect (the docs lane's stated "longest"
    // example is wrong), not a width-bound violation and not a Rust bug.
    // Left as a real, non-ignored failure rather than loosened, per the
    // brief's "report which side is wrong rather than editing either" --
    // this file does not own `event-kinds.json`.
    let longest_event_kind = fixture["widths"]["longest_event_kind"].as_str().unwrap();
    let longest_event_kind_bytes = fixture["widths"]["longest_event_kind_utf8_bytes"]
        .as_u64()
        .unwrap();
    assert!(all_event_kinds.iter().any(|k| k == longest_event_kind));
    assert_eq!(longest_event_kind.len() as u64, longest_event_kind_bytes);
    assert!(
        all_event_kinds
            .iter()
            .all(|k| k.len() as u64 <= longest_event_kind_bytes)
    );

    // `unclassified-kind-fails-closed`: self-consistency only -- proves the
    // named kind is genuinely absent from the pinned set, not that `append()`
    // rejects it (that enforcement is a producer-classification concern
    // outside this crate's `append()`/`validate()`, per PIN-4's own
    // "reversible until sign-off" status).
    let unclassified = fixture["negative_cases"]
        .as_array()
        .expect("negative_cases array")
        .iter()
        .find(|c| c["id"] == "unclassified-kind-fails-closed")
        .expect("unclassified-kind-fails-closed case");
    let unclassified_kind = unclassified["event_kind"].as_str().unwrap();
    assert!(
        !all_event_kinds.iter().any(|k| k == unclassified_kind),
        "{unclassified_kind:?} must genuinely be outside the pinned set for this case to mean anything"
    );
}

/// `rename-is-a-new-payload-version`: renaming `branch.pushed` to
/// `branch.tip_advanced` with every other field held identical must change
/// the idempotency key, proving the change rule is load-bearing (a retry
/// after a silent rename would append a second row instead of finding the
/// original).
#[test]
fn event_kind_rename_changes_the_idempotency_key() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../lorehub/docs/contracts/fixtures/lore-notification-plane/event-kinds.json");
    let text = std::fs::read_to_string(&path).expect("fixture present (checked above)");
    let fixture: Value = serde_json::from_str(&text).expect("valid JSON");
    let case = fixture["negative_cases"]
        .as_array()
        .expect("negative_cases array")
        .iter()
        .find(|c| c["id"] == "rename-is-a-new-payload-version")
        .expect("rename case");
    let before = case["before"].as_str().unwrap();
    let after = case["after"].as_str().unwrap();

    let repository_id = [7u8; 16];
    let aggregate_id = [9u8; 16];
    let version = AggregateVersion::ordinal_only(1).encode();
    let mut event = OutboxEvent {
        cell_id: "cell-a",
        repository_id: &repository_id,
        repository_generation: 3,
        event_kind: before,
        aggregate_kind: "branch",
        aggregate_id: &aggregate_id,
        aggregate_version: &version,
        payload_schema_version: 1,
        payload: b"{}",
    };
    let key_before = idempotency_key(&event);
    event.event_kind = after;
    let key_after = idempotency_key(&event);
    let expected_same = case["expected_same_idempotency_key"].as_bool().unwrap();
    assert_eq!(key_before == key_after, expected_same);
}

// ---------------------------------------------------------------------------
// cell_id width/charset (F-032-4, "Producer field widths"): at most 63
// characters, `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`. Live: reaches `append()`'s
// `validate()`, which as of this writing checks only `is_empty()` -- no
// width or charset bound. Written ahead of that landing (same convention as
// the aggregate_version width pin earlier in this file); expected to FAIL
// until `validate()` enforces F-032-4's cell_id row. This is a genuine gap
// to report, not a broken test.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn cell_id_is_bounded_at_63_chars_and_the_dns_label_charset() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping");
        return;
    };
    connect_domain_store(&url).await;
    let mut client = pg_client(&url).await;
    let version = AggregateVersion::ordinal_only(1).encode();

    async fn try_append_with_cell_id(
        client: &mut tokio_postgres::Client,
        cell_id: &str,
        version: &[u8],
    ) -> Result<(), lore_postgres::domain::DomainError> {
        let repository_id: [u8; 16] = rand::random();
        let aggregate_id: [u8; 16] = rand::random();
        let tx = client.transaction().await.expect("begin tx");
        let event = OutboxEvent {
            cell_id,
            repository_id: &repository_id,
            repository_generation: 1,
            event_kind: "branch.pushed",
            aggregate_kind: "branch",
            aggregate_id: &aggregate_id,
            aggregate_version: version,
            payload_schema_version: 1,
            payload: b"{}",
        };
        let result = append(&tx, &event).await;
        if result.is_ok() {
            tx.commit().await.expect("commit accepted append");
        } else {
            tx.rollback().await.expect("rollback rejected append");
        }
        result.map(|_| ())
    }

    // Width: 63 chars accepted, 64 rejected.
    let at_cap = format!("a{}", "b".repeat(62)); // 63 chars, valid charset
    assert_eq!(at_cap.len(), 63);
    try_append_with_cell_id(&mut client, &at_cap, &version)
        .await
        .expect("a 63-character cell_id must be accepted");
    let over_cap = format!("a{}", "b".repeat(63)); // 64 chars
    assert_eq!(over_cap.len(), 64);
    let err = try_append_with_cell_id(&mut client, &over_cap, &version)
        .await
        .expect_err("a 64-character cell_id must be rejected");
    assert!(matches!(
        err,
        lore_postgres::domain::DomainError::InvalidInput(_)
    ));

    // Charset: must start/end alphanumeric, only lowercase/digit/hyphen
    // inside, per `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`.
    for (label, cell_id) in [
        ("uppercase", "Cell-A"),
        ("underscore", "cell_a"),
        ("leading hyphen", "-cell-a"),
        ("trailing hyphen", "cell-a-"),
        ("space", "cell a"),
    ] {
        let err = try_append_with_cell_id(&mut client, cell_id, &version)
            .await
            .expect_err(&format!("cell_id {label} ({cell_id:?}) must be rejected"));
        assert!(
            matches!(err, lore_postgres::domain::DomainError::InvalidInput(_)),
            "cell_id {label}: expected InvalidInput, got {err:?}"
        );
    }
    // A single valid character is the shortest legal cell_id.
    try_append_with_cell_id(&mut client, "a", &version)
        .await
        .expect("a single lowercase-alphanumeric character must be accepted");
}

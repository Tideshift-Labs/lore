// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The bounded, transaction-local outbox append API (CR-032 base; WP-116).
//!
//! This is the whole producer surface WP-116 publishes as
//! `OUTBOX-BASE-API-READY`. It takes a caller-supplied `&Transaction`, so the
//! event row commits or rolls back with the mutation that caused it and there is
//! no second connection, no separate transaction, and no way to publish an event
//! for a mutation that did not commit.
//!
//! It deliberately does **not** dispatch, lease, claim, or acknowledge anything.
//! WP-119 owns the relay; every row this API writes stays `pending`.
//!
//! F-032-3 puts the outbox insert **last** in the shared row-lock order, after
//! `domain operation receipt -> repository -> branch -> lock namespace -> sorted
//! fragment rows -> sorted associations`. Callers are responsible for that
//! ordering; this function only appends.

use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::domain::errors::DomainError;
use crate::domain::outbox::schema::IDEMPOTENCY_KEY_DOMAIN_V1;
use crate::domain::outbox::schema::MAX_AGGREGATE_KIND_BYTES;
use crate::domain::outbox::schema::MAX_CELL_ID_BYTES;
use crate::domain::outbox::schema::MAX_EVENT_KIND_BYTES;
use crate::domain::outbox::schema::MAX_PAYLOAD_BYTES;
use crate::domain::outbox::schema::OUTBOX_STATE_PENDING;
use crate::domain::outbox::schema::is_valid_cell_id;
use crate::domain::outbox::version::validate_encoded;

/// Frozen bound on `aggregate_id`, matching the schema CHECK.
///
/// PIN(WP-119): the notification-plane contract bounds the wire envelope's
/// `aggregate_identity` at 256 UTF-8 bytes, which is wider than this. The base
/// schema's CHECK is 64 and every landed producer fits it, so the narrower
/// bound is kept: it is inside the contract's envelope accounting, and
/// widening later is compatible with every row already written while narrowing
/// would not be. Raise it with the CR owner before a producer needs more.
pub const MAX_AGGREGATE_ID_BYTES: usize = 64;
/// The `aggregate_version` **column** CHECK.
///
/// A deliberate superset of the encoded bound: SCHEMA-119 narrowed the accepted
/// values to the v1 encoding (8..=128 bytes, see
/// [`crate::domain::outbox::version`]) and `validate` enforces that, but the
/// column keeps the wider CHECK so the narrowing is a Rust-side contract rather
/// than a type change on a table.
pub const MAX_AGGREGATE_VERSION_BYTES: usize = 256;

/// One classified domain event, ready to append.
///
/// `aggregate_version` is the event-specific version a consumer compares:
/// branch generation plus exact revision hash/number, lock namespace
/// generations and fence, or fragment/association epoch. It is opaque, bounded
/// bytes here — this layer never interprets it. There is no global or
/// wall-clock event order, so `created_at` is diagnostics only and is never an
/// ordering authority.
#[derive(Debug, Clone)]
pub struct OutboxEvent<'a> {
    /// Cell identity, from trusted server configuration. Never caller-supplied.
    pub cell_id: &'a str,
    /// Repository partition the event belongs to.
    pub repository_id: &'a [u8],
    /// Repository generation committed by the causing mutation.
    pub repository_generation: i64,
    /// Classified event kind.
    pub event_kind: &'a str,
    /// Aggregate kind the event is about.
    pub aggregate_kind: &'a str,
    /// Aggregate identity within that kind.
    pub aggregate_id: &'a [u8],
    /// Committed aggregate version; opaque bounded bytes.
    pub aggregate_version: &'a [u8],
    /// Schema version of `payload`.
    pub payload_schema_version: i32,
    /// Bounded identity/version data a consumer needs to invalidate or refetch.
    /// **Not repository content.**
    pub payload: &'a [u8],
}

/// Result of one append. `created` distinguishes a first append from an exact
/// retry that found the original row, which is the only thing a caller needs in
/// order to stay idempotent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendedEvent {
    /// Stable event ID, created once and reused for every relay attempt.
    pub event_id: Uuid,
    /// The deterministic `(cell_id, idempotency_key)` half of the unique key.
    pub idempotency_key: [u8; 32],
    /// False when an exact retry matched an existing row.
    pub created: bool,
}

/// BLAKE3 over the versioned canonical tuple frozen by F-032-2: cell, event
/// kind, repository, aggregate identity, and committed aggregate version.
///
/// Every field is length-prefixed, so no two distinct tuples can serialise to
/// the same bytes by shifting a boundary. The tuple carries no secret, no
/// user-supplied path, no fragment bytes, no certificate identity, and no
/// unbounded payload — deliberately, because this key is logged and compared.
///
/// The payload itself is **not** an input: an exact mutation retry that
/// rebuilds a byte-identical payload and one that rebuilds a semantically equal
/// but not byte-identical payload must both find the original row.
pub fn idempotency_key(event: &OutboxEvent<'_>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(IDEMPOTENCY_KEY_DOMAIN_V1);
    for field in [
        event.cell_id.as_bytes(),
        event.event_kind.as_bytes(),
        event.repository_id,
        &event.repository_generation.to_be_bytes(),
        event.aggregate_kind.as_bytes(),
        event.aggregate_id,
        event.aggregate_version,
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

/// Validate every frozen bound before touching the database, so a rejected
/// event costs no transaction work and cannot leave a partial write.
fn validate(event: &OutboxEvent<'_>) -> Result<(), DomainError> {
    // The `cell_id` becomes a subject token
    // (`lore.v1.cell.<cell_id>.repo.<repository_hex>.<class>`), so its charset
    // is a safety property and not only a width: a `.`, a space, or a wildcard
    // would restructure the subject rather than fail it. Pinned by the
    // notification-plane contract's subject grammar and amendment A-8. It comes
    // from trusted server configuration, so this is defence in depth — but a
    // misconfigured cell must fail closed at append, not at the gateway after
    // the row is already durable.
    if !is_valid_cell_id(event.cell_id) {
        return Err(DomainError::InvalidInput(format!(
            "outbox cell_id must match the contract's ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ and fit \
             {MAX_CELL_ID_BYTES} bytes, got {}",
            event.cell_id.len()
        )));
    }
    if event.repository_id.len() != 16 {
        return Err(DomainError::InvalidInput(format!(
            "outbox repository_id must be 16 bytes, got {}",
            event.repository_id.len()
        )));
    }
    if event.repository_generation < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox repository_generation must be >= 1, got {}",
            event.repository_generation
        )));
    }
    if event.event_kind.is_empty() || event.aggregate_kind.is_empty() {
        return Err(DomainError::InvalidInput(
            "outbox event_kind and aggregate_kind must be non-empty".into(),
        ));
    }
    // The notification-plane contract's pinned widths. The base `CREATE TABLE`
    // declares both columns as bare `text`, so nothing but this rejects an
    // over-wide kind before it becomes a row the gateway will refuse.
    if event.event_kind.len() > MAX_EVENT_KIND_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "outbox event_kind exceeds the contract's {MAX_EVENT_KIND_BYTES}-byte width: {}",
            event.event_kind.len()
        )));
    }
    if event.aggregate_kind.len() > MAX_AGGREGATE_KIND_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "outbox aggregate_kind exceeds the contract's \
             {MAX_AGGREGATE_KIND_BYTES}-byte width: {}",
            event.aggregate_kind.len()
        )));
    }
    if event.aggregate_id.len() > MAX_AGGREGATE_ID_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "outbox aggregate_id exceeds {MAX_AGGREGATE_ID_BYTES} bytes: {}",
            event.aggregate_id.len()
        )));
    }
    // SCHEMA-119: `aggregate_version` is no longer opaque at the API boundary.
    // It must be a v1 encoding (8-byte big-endian ordinal plus 0..=120 identity
    // bytes), because a consumer that cannot decode an ordinal cannot answer
    // "older, newer, or incomparable" and must refetch instead. The column's
    // own 256-byte CHECK stays a superset of this.
    validate_encoded(event.aggregate_version)?;
    if event.payload_schema_version < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox payload_schema_version must be >= 1, got {}",
            event.payload_schema_version
        )));
    }
    if event.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "outbox payload exceeds the frozen {MAX_PAYLOAD_BYTES}-byte cap: {}",
            event.payload.len()
        )));
    }
    Ok(())
}

/// Append one event inside the caller's mutation transaction.
///
/// Exact-key retry is a single statement: `ON CONFLICT DO NOTHING` returns no
/// row when the event already exists, and the follow-up select loads the
/// original `event_id`. Both run under the same transaction, so a concurrent
/// first-writer is serialised by the unique index rather than by a read-then-
/// write race.
///
/// `created_at`/`available_at` come from Postgres `clock_timestamp()`. A process
/// clock is never a time authority in this crate.
pub async fn append(
    tx: &Transaction<'_>,
    event: &OutboxEvent<'_>,
) -> Result<AppendedEvent, DomainError> {
    validate(event)?;
    let key = idempotency_key(event);
    let event_id = Uuid::new_v4();

    let inserted = tx
        .query_opt(
            "INSERT INTO lore_outbox_events ( \
                 event_id, cell_id, idempotency_key, \
                 repository_id, repository_generation, \
                 event_kind, aggregate_kind, aggregate_id, aggregate_version, \
                 payload_schema_version, payload, \
                 state, created_at, available_at \
             ) VALUES ( \
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                 clock_timestamp(), clock_timestamp() \
             ) \
             ON CONFLICT (cell_id, idempotency_key) DO NOTHING \
             RETURNING event_id",
            &[
                &event_id,
                &event.cell_id,
                &key.as_slice(),
                &event.repository_id,
                &event.repository_generation,
                &event.event_kind,
                &event.aggregate_kind,
                &event.aggregate_id,
                &event.aggregate_version,
                &event.payload_schema_version,
                &event.payload,
                &OUTBOX_STATE_PENDING,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox append", e))?;

    if inserted.is_some() {
        return Ok(AppendedEvent {
            event_id,
            idempotency_key: key,
            created: true,
        });
    }

    // Exact retry: the original row wins and keeps its stable event ID.
    let existing = tx
        .query_one(
            "SELECT event_id FROM lore_outbox_events \
             WHERE cell_id = $1 AND idempotency_key = $2",
            &[&event.cell_id, &key.as_slice()],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox append exact-retry lookup", e))?;

    Ok(AppendedEvent {
        event_id: existing.get("event_id"),
        idempotency_key: key,
        created: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::outbox::version::AggregateVersion;
    use crate::domain::outbox::version::MAX_ENCODED_AGGREGATE_VERSION_BYTES;

    /// A minimal well-formed `aggregate_version`: SCHEMA-119's `validate`
    /// rejects anything that is not a v1 encoding, so the `validate_*` cases
    /// below need a real one or they would all pass for the wrong reason.
    fn version_bytes(ordinal: u64) -> Vec<u8> {
        AggregateVersion::ordinal_only(ordinal).encode()
    }

    fn event<'a>(kind: &'a str, version: &'a [u8]) -> OutboxEvent<'a> {
        OutboxEvent {
            cell_id: "cell-a",
            repository_id: &[7u8; 16],
            repository_generation: 3,
            event_kind: kind,
            aggregate_kind: "branch",
            aggregate_id: &[9u8; 16],
            aggregate_version: version,
            payload_schema_version: 1,
            payload: b"{}",
        }
    }

    #[test]
    fn idempotency_key_is_stable_and_payload_independent() {
        let a = event("branch.pushed", b"v1");
        let mut b = event("branch.pushed", b"v1");
        b.payload = b"{\"different\":true}";
        assert_eq!(idempotency_key(&a), idempotency_key(&b));
    }

    #[test]
    fn idempotency_key_separates_adjacent_fields() {
        // Without length prefixes these two tuples would serialise identically.
        let a = event("ab", b"c");
        let b = event("a", b"bc");
        assert_ne!(idempotency_key(&a), idempotency_key(&b));
    }

    #[test]
    fn idempotency_key_covers_generation() {
        let a = event("branch.pushed", b"v1");
        let mut b = event("branch.pushed", b"v1");
        b.repository_generation = 4;
        assert_ne!(idempotency_key(&a), idempotency_key(&b));
    }

    #[test]
    fn validate_rejects_oversized_payload() {
        let version = version_bytes(1);
        let big = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let mut e = event("branch.pushed", &version);
        e.payload = &big;
        assert!(matches!(validate(&e), Err(DomainError::InvalidInput(_))));
    }

    #[test]
    fn validate_accepts_payload_at_the_cap() {
        let version = version_bytes(1);
        let exact = vec![0u8; MAX_PAYLOAD_BYTES];
        let mut e = event("branch.pushed", &version);
        e.payload = &exact;
        assert!(validate(&e).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_repository_id_length() {
        let version = version_bytes(1);
        let mut e = event("branch.pushed", &version);
        e.repository_id = &[1u8; 15];
        assert!(matches!(validate(&e), Err(DomainError::InvalidInput(_))));
    }

    /// SCHEMA-119's narrowing. The column CHECK still admits 256 bytes and the
    /// old API admitted anything under it, so only this rejects a version a
    /// consumer could not decode an ordinal from.
    #[test]
    fn validate_rejects_an_aggregate_version_that_is_not_a_v1_encoding() {
        let e = event("branch.pushed", b"v1");
        assert!(matches!(validate(&e), Err(DomainError::InvalidInput(_))));

        let too_wide = vec![0u8; MAX_ENCODED_AGGREGATE_VERSION_BYTES + 1];
        let e = event("branch.pushed", &too_wide);
        assert!(matches!(validate(&e), Err(DomainError::InvalidInput(_))));

        let widest = vec![0u8; MAX_ENCODED_AGGREGATE_VERSION_BYTES];
        let e = event("branch.pushed", &widest);
        assert!(validate(&e).is_ok());
    }

    /// The contract's pinned kind widths. Both columns are bare `text`, so
    /// `validate` is the only thing that can reject an over-wide kind.
    #[test]
    fn validate_rejects_kinds_wider_than_the_contract() {
        let version = version_bytes(1);
        let wide = "k".repeat(MAX_EVENT_KIND_BYTES + 1);

        let mut e = event("branch.pushed", &version);
        e.event_kind = &wide;
        assert!(matches!(validate(&e), Err(DomainError::InvalidInput(_))));

        let mut e = event("branch.pushed", &version);
        e.aggregate_kind = &wide;
        assert!(matches!(validate(&e), Err(DomainError::InvalidInput(_))));

        let at_cap = "k".repeat(MAX_EVENT_KIND_BYTES);
        let mut e = event("branch.pushed", &version);
        e.event_kind = &at_cap;
        e.aggregate_kind = &at_cap;
        assert!(validate(&e).is_ok());
    }
}

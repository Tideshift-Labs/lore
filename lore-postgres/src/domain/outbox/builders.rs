// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Transaction-local event builders for the pinned CR-032 event set (WP-116).
//!
//! CR-032's "Transaction-local API and mutation integration" says the append
//! API "accepts bounded typed event records from domain-owned builders". This
//! module is that set of builders. Each one produces a
//! [`PendingEvent`](crate::domain::coordinator::PendingEvent) for exactly one
//! `event_kind` from the pinned value set, with the `aggregate_kind`,
//! `aggregate_id`, and `aggregate_version` shape that kind is assigned.
//!
//! # Why a builder per kind rather than one constructor with arguments
//!
//! The pinned set fixes five things per kind at once — the `event_kind` string,
//! the `aggregate_kind` string, what `aggregate_id` holds, what the ordinal
//! half of `aggregate_version` is, and what its identity half is. Those five
//! are not independent, and a single constructor taking all of them would let a
//! caller pair `branch.pushed` with a repository aggregate id and still
//! compile. Every one of those strings and bytes travels inside the frozen
//! `idempotency_key` preimage, so a wrong pairing is not a display bug: it
//! permanently mis-keys the event and an exact mutation retry appends a second
//! row instead of finding its original.
//!
//! # The ordinal is not an argument
//!
//! F-032-4's ordinal is the version the transaction **committed**, which for
//! four of the six append-capable coordinator methods is only known inside that
//! transaction. So these builders name the committed value they want with a
//! [`CommittedOrdinal`] and the coordinator's append step resolves it. See that
//! type's own documentation for why a caller-supplied ordinal would be wrong
//! rather than merely awkward.
//!
//! # Sources
//!
//! * Pinned value set: CR-032 "Pinned `event_kind` and `aggregate_kind` values
//!   (2026-09-03, PIN-4)" and
//!   `lorehub/docs/contracts/fixtures/lore-notification-plane/event-kinds.json`.
//! * `aggregate_version` encoding: CR-032 F-032-4 / PIN-2 and
//!   `.../aggregate-version.json`, implemented in
//!   [`crate::domain::outbox::version`].
//! * `repository.obliterated`: CR-032 PIN-3.
//!
//! # Ownership
//!
//! WP-119 Phase 4 splits the *emission call sites*: WP-116 owns repository and
//! branch, WP-117 the five `lock_namespace` kinds, WP-118 the two summary
//! kinds. The builders themselves are all here so that the pinned set has one
//! home and one place a value-set change is made; a builder is a pure function
//! and constructing one is not a producer call site.

use std::fmt::Write as _;

use crate::domain::coordinator::CommittedOrdinal;
use crate::domain::coordinator::PendingEvent;
use crate::domain::errors::DomainError;
use crate::domain::outbox::schema::MAX_PAYLOAD_BYTES;
use crate::domain::outbox::version::MAX_AGGREGATE_VERSION_IDENTITY_BYTES;

/// `payload_schema_version` every builder here emits.
///
/// CR-032 makes a change to any pinned `event_kind` string a new payload schema
/// version rather than an in-place rename, so this constant and the strings
/// below move together or not at all.
pub const PAYLOAD_SCHEMA_VERSION_V1: i32 = 1;

// --- Pinned `aggregate_kind` values ---------------------------------------

/// Repository-level aggregate.
pub const AGGREGATE_REPOSITORY: &str = "repository";
/// Branch-level aggregate.
pub const AGGREGATE_BRANCH: &str = "branch";
/// Lock-namespace aggregate.
pub const AGGREGATE_LOCK_NAMESPACE: &str = "lock_namespace";
/// Per-repository fragment lifecycle summary aggregate.
pub const AGGREGATE_FRAGMENT_LIFECYCLE: &str = "fragment_lifecycle";
/// Per-repository content-association summary aggregate.
pub const AGGREGATE_ASSOCIATION: &str = "association";

// --- Pinned `event_kind` values -------------------------------------------

/// A repository became live.
pub const REPOSITORY_PUBLISHED: &str = "repository.published";
/// A repository's metadata pointer changed.
pub const REPOSITORY_METADATA_CHANGED: &str = "repository.metadata_changed";
/// A repository's default branch changed.
pub const REPOSITORY_DEFAULT_BRANCH_CHANGED: &str = "repository.default_branch_changed";
/// A repository was tombstoned.
pub const REPOSITORY_TOMBSTONED: &str = "repository.tombstoned";
/// An address obliteration fence committed (PIN-3).
pub const REPOSITORY_OBLITERATED: &str = "repository.obliterated";

/// A branch was created.
pub const BRANCH_CREATED: &str = "branch.created";
/// A branch's metadata pointer changed.
pub const BRANCH_METADATA_CHANGED: &str = "branch.metadata_changed";
/// A branch's protection state changed.
pub const BRANCH_PROTECTION_CHANGED: &str = "branch.protection_changed";
/// A branch tip advanced.
pub const BRANCH_PUSHED: &str = "branch.pushed";
/// A branch was tombstoned.
pub const BRANCH_DELETED: &str = "branch.deleted";

/// A lock was first acquired.
pub const LOCK_ACQUIRED: &str = "lock.acquired";
/// A lock was renewed by its current owner.
pub const LOCK_RENEWED: &str = "lock.renewed";
/// An expired lock was taken over.
pub const LOCK_TAKEN_OVER: &str = "lock.taken_over";
/// A lock was released by its owner.
pub const LOCK_RELEASED: &str = "lock.released";
/// A lock was force-released.
pub const LOCK_FORCE_RELEASED: &str = "lock.force_released";

/// The bounded per-repository fragment lifecycle summary.
pub const FRAGMENT_LIFECYCLE_GENERATION_ADVANCED: &str = "fragment.lifecycle_generation_advanced";
/// The bounded per-repository association summary.
pub const ASSOCIATION_GENERATION_ADVANCED: &str = "association.generation_advanced";

/// Every pinned `event_kind`, in the order CR-032's table lists them.
///
/// Exists so the value set can be asserted whole rather than one literal at a
/// time: CR-032 makes an unclassified kind fail closed, and a set that has
/// silently grown or shrunk is the way that rule stops holding.
pub const PINNED_EVENT_KINDS: [&str; 17] = [
    REPOSITORY_PUBLISHED,
    REPOSITORY_METADATA_CHANGED,
    REPOSITORY_DEFAULT_BRANCH_CHANGED,
    REPOSITORY_TOMBSTONED,
    REPOSITORY_OBLITERATED,
    BRANCH_CREATED,
    BRANCH_METADATA_CHANGED,
    BRANCH_PROTECTION_CHANGED,
    BRANCH_PUSHED,
    BRANCH_DELETED,
    LOCK_ACQUIRED,
    LOCK_RENEWED,
    LOCK_TAKEN_OVER,
    LOCK_RELEASED,
    LOCK_FORCE_RELEASED,
    FRAGMENT_LIFECYCLE_GENERATION_ADVANCED,
    ASSOCIATION_GENERATION_ADVANCED,
];

/// Every pinned `aggregate_kind`.
pub const PINNED_AGGREGATE_KINDS: [&str; 5] = [
    AGGREGATE_REPOSITORY,
    AGGREGATE_BRANCH,
    AGGREGATE_LOCK_NAMESPACE,
    AGGREGATE_FRAGMENT_LIFECYCLE,
    AGGREGATE_ASSOCIATION,
];

/// Frozen bound on an `aggregate_id`, re-exported from the append API so a
/// builder refuses an over-wide id before the transaction opens rather than
/// at the INSERT.
///
/// Only the `lock_namespace` aggregate can approach it: its `aggregate_id` is a
/// namespace string, while every other pinned aggregate keys on a 16-byte id.
///
/// The branch aggregate used to be the exposure here, and briefly carried a
/// `BLOCKED(WP-116)` record. PIN-4 originally made the branch `aggregate_id`
/// the branch name in UTF-8, which Lore admits up to
/// `lore_revision::branch::MAX_NAME_LEN` (1,000 bytes), so a legal branch had
/// no expressible outbox identity. CR-032's "Branch `aggregate_id` amendment,
/// 2026-09-03 (second amendment to PIN-4)" resolved it: the branch
/// `aggregate_id` is the 16-byte branch id and the name travels in the bounded
/// payload. Truncation was rejected outright, because a 64-byte prefix of two
/// long names can collide and would dedupe two branches' events onto one
/// `idempotency_key`.
pub const MAX_AGGREGATE_ID_BYTES: usize = crate::domain::outbox::append::MAX_AGGREGATE_ID_BYTES;

/// Build the bounded payload.
///
/// Field names are `&'static str` on purpose: they are emitted unescaped, and
/// typing them as literals is what makes that safe by construction rather
/// than by the current call sites happening to pass constants.
///
/// Deliberately hand-rolled rather than a serialiser: the payload is a short,
/// closed set of hex-encoded identity fields, and CR-032 caps it at 64 KiB and
/// forbids repository content in it. Writing the object by hand keeps both
/// properties readable at the call site instead of hidden behind a derive.
///
/// The payload is **not** an input to `idempotency_key`, so this encoding is
/// not frozen the way the kind strings are; it is deterministic anyway, because
/// a payload that varies between an original and its retry is confusing
/// evidence even when it is not a correctness problem.
fn payload(fields: &[(&'static str, PayloadValue<'_>)]) -> Vec<u8> {
    let mut out = String::from("{");
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(name);
        out.push_str("\":");
        match value {
            PayloadValue::Hex(bytes) => {
                out.push('"');
                out.push_str(&hex::encode(bytes));
                out.push('"');
            }
            PayloadValue::Text(text) => {
                out.push('"');
                for ch in text.chars() {
                    match ch {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => {
                            // `write!` into the buffer rather than
                            // `format!` into a temporary. Writing to a `String`
                            // cannot fail, which is why the result is dropped.
                            let _ = write!(out, "\\u{:04x}", c as u32);
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            PayloadValue::Bool(value) => {
                out.push_str(if *value { "true" } else { "false" });
            }
        }
    }
    out.push('}');
    out.into_bytes()
}

/// The three shapes a payload field can take.
enum PayloadValue<'a> {
    /// Raw bytes, hex-encoded.
    Hex(&'a [u8]),
    /// UTF-8 text, JSON-escaped.
    Text(&'a str),
    /// A flag.
    Bool(bool),
}

/// Reject an identity half that cannot fit F-032-4's encoding.
///
/// [`crate::domain::outbox::version::AggregateVersion::new`] would reject it
/// too, but only once the coordinator resolves the ordinal — which happens
/// inside the mutation transaction, after the domain rows are written. Checking
/// at build time turns that into a refusal before the transaction opens.
fn checked_identity(identity: Vec<u8>, kind: &str) -> Result<Vec<u8>, DomainError> {
    if identity.len() > MAX_AGGREGATE_VERSION_IDENTITY_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "{kind} aggregate_version identity exceeds \
             {MAX_AGGREGATE_VERSION_IDENTITY_BYTES} bytes: {}",
            identity.len()
        )));
    }
    Ok(identity)
}

/// Reject an over-wide lock-namespace `aggregate_id` before the transaction
/// opens.
///
/// `lock_namespace` is the only pinned aggregate whose `aggregate_id` is a
/// variable-width string. Every other kind keys on a 16-byte id and goes
/// through [`checked_id_16`] instead.
fn checked_namespace_id(aggregate_id: Vec<u8>, kind: &str) -> Result<Vec<u8>, DomainError> {
    if aggregate_id.len() > MAX_AGGREGATE_ID_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "{kind} aggregate_id exceeds {MAX_AGGREGATE_ID_BYTES} bytes: {}",
            aggregate_id.len()
        )));
    }
    Ok(aggregate_id)
}

/// Reject an over-cap payload before the transaction opens.
///
/// `append` enforces the same cap, but only once the mutation transaction is
/// already open, so an overrun there rolls back committed domain work instead
/// of rejecting a request. Unreachable today, since the widest field is a
/// 1,000-byte branch name, but the missing symmetry with every sibling check is
/// the defect, not the reachability.
fn checked_payload(payload: Vec<u8>, kind: &str) -> Result<Vec<u8>, DomainError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "{kind} payload is {} bytes, over the frozen {MAX_PAYLOAD_BYTES}-byte cap",
            payload.len()
        )));
    }
    Ok(payload)
}

/// Reject an identity that is not the 16 bytes an id-keyed aggregate uses.
///
/// Both the repository and, since CR-032's 2026-09-03 branch amendment, the
/// branch aggregate key on exactly 16 bytes, so one check serves both; `field`
/// keeps the diagnostic specific about which one was wrong.
fn checked_id_16(id: &[u8], kind: &str, field: &str) -> Result<Vec<u8>, DomainError> {
    if id.len() != 16 {
        return Err(DomainError::InvalidInput(format!(
            "{kind} {field} must be 16 bytes, got {}",
            id.len()
        )));
    }
    Ok(id.to_vec())
}

// --- Repository aggregate --------------------------------------------------
//
// `aggregate_id` is the 16 raw repository bytes, the ordinal is the committed
// repository generation, and the identity is empty. That is the whole shape for
// all five repository kinds, so they differ only in the classified kind string
// and in what their bounded payload names.

fn repository_event(
    cell_id: &str,
    repository_id: &[u8],
    event_kind: &'static str,
    payload: Vec<u8>,
) -> Result<PendingEvent, DomainError> {
    Ok(PendingEvent {
        cell_id: cell_id.to_owned(),
        event_kind: event_kind.to_owned(),
        aggregate_kind: AGGREGATE_REPOSITORY.to_owned(),
        aggregate_id: checked_id_16(repository_id, event_kind, "repository_id")?,
        aggregate_ordinal: CommittedOrdinal::RepositoryGeneration,
        aggregate_identity: Vec::new(),
        payload_schema_version: PAYLOAD_SCHEMA_VERSION_V1,
        payload: checked_payload(payload, event_kind)?,
    })
}

/// `repository.published` — a repository became live.
pub fn repository_published(
    cell_id: &str,
    repository_id: &[u8],
    name: &str,
    default_branch_id: &[u8],
    default_branch_name: &str,
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        ("name", PayloadValue::Text(name)),
        ("default_branch_id", PayloadValue::Hex(default_branch_id)),
        (
            "default_branch_name",
            PayloadValue::Text(default_branch_name),
        ),
    ]);
    repository_event(cell_id, repository_id, REPOSITORY_PUBLISHED, payload)
}

/// `repository.metadata_changed` — the repository metadata pointer moved.
pub fn repository_metadata_changed(
    cell_id: &str,
    repository_id: &[u8],
    previous_metadata_hash: &[u8],
    new_metadata_hash: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        (
            "previous_metadata_hash",
            PayloadValue::Hex(previous_metadata_hash),
        ),
        ("new_metadata_hash", PayloadValue::Hex(new_metadata_hash)),
    ]);
    repository_event(cell_id, repository_id, REPOSITORY_METADATA_CHANGED, payload)
}

/// `repository.default_branch_changed` — the default branch pointer moved.
///
/// PIN(WP-116): CR-032's pinned set keeps this distinct from
/// `repository.metadata_changed`, and the fixture's first open question is
/// whether it should stay distinct given that both travel the same metadata CAS
/// writer. The builder exists because the value is pinned; it has no emission
/// call site until a writer can tell the two transitions apart, which the
/// current CAS cannot. Resolving the open question by removing the value
/// removes this builder.
pub fn repository_default_branch_changed(
    cell_id: &str,
    repository_id: &[u8],
    previous_default_branch_id: &[u8],
    new_default_branch_id: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        (
            "previous_default_branch_id",
            PayloadValue::Hex(previous_default_branch_id),
        ),
        (
            "new_default_branch_id",
            PayloadValue::Hex(new_default_branch_id),
        ),
    ]);
    repository_event(
        cell_id,
        repository_id,
        REPOSITORY_DEFAULT_BRANCH_CHANGED,
        payload,
    )
}

/// `repository.tombstoned` — the repository was deleted.
pub fn repository_tombstoned(
    cell_id: &str,
    repository_id: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[("repository_id", PayloadValue::Hex(repository_id))]);
    repository_event(cell_id, repository_id, REPOSITORY_TOMBSTONED, payload)
}

/// `repository.obliterated` — the CR-032 PIN-3 address-obliteration fence.
///
/// The payload names the obliterated address because a consumer that has to
/// invalidate cached content needs to know which one; the aggregate version
/// stays the repository generation, exactly as PIN-3 pins it, because the fence
/// is what the mutation committed.
pub fn repository_obliterated(
    cell_id: &str,
    repository_id: &[u8],
    address_hash: &[u8],
    address_context: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        ("address_hash", PayloadValue::Hex(address_hash)),
        ("address_context", PayloadValue::Hex(address_context)),
    ]);
    repository_event(cell_id, repository_id, REPOSITORY_OBLITERATED, payload)
}

// --- Branch aggregate ------------------------------------------------------
//
// `aggregate_id` is the 16 raw branch-id bytes, per CR-032's 2026-09-03 branch
// amendment. The ordinal is the committed branch generation and the identity is
// the exact revision hash. The branch NAME is not an identity here: it travels
// in the bounded payload, where a consumer that needs it for display reads it
// without any width risk.

fn branch_event(
    cell_id: &str,
    branch_id: &[u8],
    event_kind: &'static str,
    revision_hash: &[u8],
    payload: Vec<u8>,
) -> Result<PendingEvent, DomainError> {
    Ok(PendingEvent {
        cell_id: cell_id.to_owned(),
        event_kind: event_kind.to_owned(),
        aggregate_kind: AGGREGATE_BRANCH.to_owned(),
        aggregate_id: checked_id_16(branch_id, event_kind, "branch_id")?,
        aggregate_ordinal: CommittedOrdinal::BranchGeneration,
        aggregate_identity: checked_identity(revision_hash.to_vec(), event_kind)?,
        payload_schema_version: PAYLOAD_SCHEMA_VERSION_V1,
        payload: checked_payload(payload, event_kind)?,
    })
}

/// `branch.created` — a branch was created at an initial tip.
pub fn branch_created(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    branch_name: &str,
    latest_hash: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        ("branch_id", PayloadValue::Hex(branch_id)),
        ("branch_name", PayloadValue::Text(branch_name)),
        ("latest_hash", PayloadValue::Hex(latest_hash)),
    ]);
    branch_event(cell_id, branch_id, BRANCH_CREATED, latest_hash, payload)
}

/// `branch.metadata_changed` — a branch metadata pointer moved.
///
/// The `aggregate_version` identity stays the branch's current tip rather than
/// the metadata hash: the pinned set assigns `exact revision hash` to every
/// branch kind, and a consumer that compared two different meanings of
/// "identity" under one aggregate would read a metadata change as a tip
/// disagreement.
pub fn branch_metadata_changed(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    branch_name: &str,
    latest_hash: &[u8],
    previous_metadata_hash: &[u8],
    new_metadata_hash: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        ("branch_id", PayloadValue::Hex(branch_id)),
        ("branch_name", PayloadValue::Text(branch_name)),
        (
            "previous_metadata_hash",
            PayloadValue::Hex(previous_metadata_hash),
        ),
        ("new_metadata_hash", PayloadValue::Hex(new_metadata_hash)),
    ]);
    branch_event(
        cell_id,
        branch_id,
        BRANCH_METADATA_CHANGED,
        latest_hash,
        payload,
    )
}

/// `branch.protection_changed` — a branch's protection flag moved.
///
/// PIN(WP-116): the fixture's second open question is whether this stays
/// distinct from `branch.metadata_changed`, since the protect toggle travels
/// inside the same metadata CAS while `BranchProtect`/`BranchUnprotect` are
/// separate RPCs that write no metadata and hold no domain context at all
/// (WP-119 inventory B9, B10, disagreement D2). The builder exists because the
/// value is pinned; it has no emission call site until one of those two writers
/// is governed.
pub fn branch_protection_changed(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    branch_name: &str,
    latest_hash: &[u8],
    protected: bool,
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        ("branch_id", PayloadValue::Hex(branch_id)),
        ("branch_name", PayloadValue::Text(branch_name)),
        ("protected", PayloadValue::Bool(protected)),
    ]);
    branch_event(
        cell_id,
        branch_id,
        BRANCH_PROTECTION_CHANGED,
        latest_hash,
        payload,
    )
}

/// `branch.pushed` — a branch tip advanced to `new_latest_hash`.
///
/// Only a real advance builds one. A push of the current head is a successful
/// idempotent no-op and emits nothing; that suppression is enforced in the
/// coordinator, which returns before its append step, rather than trusted to
/// the caller. See `branch_push_commit`.
pub fn branch_pushed(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    branch_name: &str,
    previous_latest_hash: &[u8],
    new_latest_hash: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        ("branch_id", PayloadValue::Hex(branch_id)),
        ("branch_name", PayloadValue::Text(branch_name)),
        (
            "previous_latest_hash",
            PayloadValue::Hex(previous_latest_hash),
        ),
        ("new_latest_hash", PayloadValue::Hex(new_latest_hash)),
    ]);
    branch_event(cell_id, branch_id, BRANCH_PUSHED, new_latest_hash, payload)
}

/// `branch.deleted` — a branch was tombstoned at its final tip.
pub fn branch_deleted(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    branch_name: &str,
    final_latest_hash: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        ("branch_id", PayloadValue::Hex(branch_id)),
        ("branch_name", PayloadValue::Text(branch_name)),
        ("final_latest_hash", PayloadValue::Hex(final_latest_hash)),
    ]);
    branch_event(
        cell_id,
        branch_id,
        BRANCH_DELETED,
        final_latest_hash,
        payload,
    )
}

// --- Lock-namespace aggregate ---------------------------------------------
//
// WP-117 owns these emission call sites (WP-119 Phase 4). The builders live
// here with the rest of the pinned set. `aggregate_id` is the lock namespace in
// UTF-8, the ordinal is the committed `last_applied_fence`, and the identity is
// the lock owner token.
//
// The fence and the owner token are both produced **inside** the lock
// coordinator's transaction — the fence from a sequence, the token from a
// CSPRNG — so these builders take them as arguments rather than pretending a
// handler could know them. The ordinal is therefore `Exact`: by the time the
// coordinator can call one of these it already holds the committed fence.

fn lock_event(
    cell_id: &str,
    namespace: &str,
    event_kind: &'static str,
    committed_fence: u64,
    owner_token: &[u8],
    payload: Vec<u8>,
) -> Result<PendingEvent, DomainError> {
    Ok(PendingEvent {
        cell_id: cell_id.to_owned(),
        event_kind: event_kind.to_owned(),
        aggregate_kind: AGGREGATE_LOCK_NAMESPACE.to_owned(),
        aggregate_id: checked_namespace_id(namespace.as_bytes().to_vec(), event_kind)?,
        aggregate_ordinal: CommittedOrdinal::Exact(committed_fence),
        aggregate_identity: checked_identity(owner_token.to_vec(), event_kind)?,
        payload_schema_version: PAYLOAD_SCHEMA_VERSION_V1,
        payload: checked_payload(payload, event_kind)?,
    })
}

fn lock_payload(repository_id: &[u8], branch_id: &[u8], namespace: &str, owner: &str) -> Vec<u8> {
    payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        ("branch_id", PayloadValue::Hex(branch_id)),
        ("namespace", PayloadValue::Text(namespace)),
        ("owner", PayloadValue::Text(owner)),
    ])
}

/// `lock.acquired` — a first acquire by this owner.
pub fn lock_acquired(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    namespace: &str,
    owner: &str,
    committed_fence: u64,
    owner_token: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = lock_payload(repository_id, branch_id, namespace, owner);
    lock_event(
        cell_id,
        namespace,
        LOCK_ACQUIRED,
        committed_fence,
        owner_token,
        payload,
    )
}

/// `lock.renewed` — a same-owner renewal.
pub fn lock_renewed(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    namespace: &str,
    owner: &str,
    committed_fence: u64,
    owner_token: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = lock_payload(repository_id, branch_id, namespace, owner);
    lock_event(
        cell_id,
        namespace,
        LOCK_RENEWED,
        committed_fence,
        owner_token,
        payload,
    )
}

/// `lock.taken_over` — an expired lock changed owner.
///
/// PIN(WP-116): the fixture's fourth open question is whether this value can
/// exist before an expiry-takeover writer is built. The WP-119 inventory found
/// none on the production path, and this builder does not create one.
pub fn lock_taken_over(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    namespace: &str,
    owner: &str,
    committed_fence: u64,
    owner_token: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = lock_payload(repository_id, branch_id, namespace, owner);
    lock_event(
        cell_id,
        namespace,
        LOCK_TAKEN_OVER,
        committed_fence,
        owner_token,
        payload,
    )
}

/// `lock.released` — the owner released.
pub fn lock_released(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    namespace: &str,
    owner: &str,
    committed_fence: u64,
    owner_token: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = lock_payload(repository_id, branch_id, namespace, owner);
    lock_event(
        cell_id,
        namespace,
        LOCK_RELEASED,
        committed_fence,
        owner_token,
        payload,
    )
}

/// `lock.force_released` — an administrative release.
pub fn lock_force_released(
    cell_id: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    namespace: &str,
    owner: &str,
    committed_fence: u64,
    owner_token: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = lock_payload(repository_id, branch_id, namespace, owner);
    lock_event(
        cell_id,
        namespace,
        LOCK_FORCE_RELEASED,
        committed_fence,
        owner_token,
        payload,
    )
}

// --- Summary aggregates ----------------------------------------------------
//
// WP-118 owns these emission call sites. Both are the bounded per-repository
// generation summaries CR-032 requires instead of one row per fragment or
// association, so `aggregate_id` is the 16 repository bytes for both.

/// `fragment.lifecycle_generation_advanced` — the bounded per-repository
/// fragment-lifecycle summary.
///
/// The ordinal is the committed `fragment_lifecycle_generation`, which is not
/// the repository generation, so it is passed explicitly.
pub fn fragment_lifecycle_generation_advanced(
    cell_id: &str,
    repository_id: &[u8],
    committed_lifecycle_generation: u64,
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[("repository_id", PayloadValue::Hex(repository_id))]);
    Ok(PendingEvent {
        cell_id: cell_id.to_owned(),
        event_kind: FRAGMENT_LIFECYCLE_GENERATION_ADVANCED.to_owned(),
        aggregate_kind: AGGREGATE_FRAGMENT_LIFECYCLE.to_owned(),
        aggregate_id: checked_id_16(
            repository_id,
            FRAGMENT_LIFECYCLE_GENERATION_ADVANCED,
            "repository_id",
        )?,
        aggregate_ordinal: CommittedOrdinal::Exact(committed_lifecycle_generation),
        aggregate_identity: Vec::new(),
        payload_schema_version: PAYLOAD_SCHEMA_VERSION_V1,
        payload: checked_payload(payload, FRAGMENT_LIFECYCLE_GENERATION_ADVANCED)?,
    })
}

/// `association.generation_advanced` — the bounded per-repository association
/// summary.
///
/// The identity half is the committed `association_epoch` bytes, per the pinned
/// set. WP-119's inventory records that `tombstone_association` does not move
/// that epoch (disagreement D8); that is a WP-118 writer defect, not something
/// this builder can paper over, so an epoch it is handed is the epoch it
/// publishes.
pub fn association_generation_advanced(
    cell_id: &str,
    repository_id: &[u8],
    committed_association_generation: u64,
    association_epoch: &[u8],
) -> Result<PendingEvent, DomainError> {
    let payload = payload(&[
        ("repository_id", PayloadValue::Hex(repository_id)),
        ("association_epoch", PayloadValue::Hex(association_epoch)),
    ]);
    Ok(PendingEvent {
        cell_id: cell_id.to_owned(),
        event_kind: ASSOCIATION_GENERATION_ADVANCED.to_owned(),
        aggregate_kind: AGGREGATE_ASSOCIATION.to_owned(),
        aggregate_id: checked_id_16(
            repository_id,
            ASSOCIATION_GENERATION_ADVANCED,
            "repository_id",
        )?,
        aggregate_ordinal: CommittedOrdinal::Exact(committed_association_generation),
        aggregate_identity: checked_identity(
            association_epoch.to_vec(),
            ASSOCIATION_GENERATION_ADVANCED,
        )?,
        payload_schema_version: PAYLOAD_SCHEMA_VERSION_V1,
        payload: checked_payload(payload, ASSOCIATION_GENERATION_ADVANCED)?,
    })
}

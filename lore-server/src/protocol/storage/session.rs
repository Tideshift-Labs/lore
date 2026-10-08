// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use dashmap::DashMap;
use dashmap::DashSet;
use lore_revision::lore::RepositoryId;

use crate::authnz::repository_authorizer::Grants;
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::authnz::repository_authorizer::VerifiedTokenOwned;

#[lore_macro::test_pub]
#[lore_macro::test_pub]
pub(crate) const MAX_CONCURRENT_SESSIONS: u32 = 10_000;

/// Session ids come from one process-wide sequence, not from a counter per [`SessionMap`].
///
/// A `SessionMap` is per accepted connection, so a per-map counter restarting at 1 meant two
/// live connections each held a session numbered 1. Nothing on the wire distinguishes them: a
/// storage command carrying an id issued on one connection is bit-for-bit identical to the same
/// command carrying this connection's own, and the server resolved it against whichever session
/// owned that number here — executing the command under a different repository, user and
/// permission set, or stopping an unrelated live session (INV-EO P0-1 and P0-2).
///
/// Allocating from one sequence makes the id spaces of every `SessionMap` in the process
/// disjoint, so an id from another connection on this server resolves to nothing and the command
/// is refused. That is a property of the id rather than of the client's timing, so it holds for
/// any client, including one that does not check before sending.
///
/// **Two limits, stated because neither is obvious and both matter.**
///
/// It is *per process*. A deployment runs many loreserver processes, and a client that
/// reconnects onto a different one is not protected by the disjointness above at all: it is
/// protected only by the two sequences having started somewhere far apart, which is why the seed
/// is random rather than 1. The odds that a stale id happens to name a live session in the other
/// process are roughly that process's live session count over 2^32. At
/// [`MAX_CONCURRENT_SESSIONS`] that is 10,000 / 2^32, or about one in 429,497 per attempt, not one
/// in four billion. This is small enough for the random seed to remain a useful cross-process
/// mitigation, but it is not the isolation guarantee. The client generation check is.
///
/// It holds *until the sequence wraps*. [`SessionMap::allocate`] redraws against the occupancy of
/// its own map only, because that is the only map it can see; it cannot tell that a sibling
/// connection holds the number live. So after 2^32 allocations in one process, two maps can
/// again hold the same id, which is P0-1's original condition.
///
/// The guarantee for both cases is the client's, not this one's: our transport records the
/// connection generation each id was issued on and refuses to frame an id whose generation has
/// moved, whichever server it would have reached (`QuicConnection::session_is_current` in
/// `lore-transport`). What this sequence buys is that a client *without* that check — a stock
/// `lore` CLI — is covered for the ordinary case of two live connections to one server.
static NEXT_SESSION_ID: LazyLock<AtomicU32> = LazyLock::new(|| AtomicU32::new(rand::random()));

pub struct SessionEntry {
    pub repository: RepositoryId,
    pub correlation_id: String,
    pub user_id: String,
    /// Effective permission strings for this session's repository, snapshotted
    /// from the verified token at `AuthorizeStart` (union across matching
    /// resources, wildcard included). Empty when auth is off or the token
    /// carried no matching `permission` entries. Storage commands have no
    /// per-request token, so the fork's write-permission enforcement reads
    /// this (FORK-LOCAL: upstream has no `write` action; `grants` below is
    /// upstream's per-action answer and does not replace it).
    pub permissions: Vec<String>,
    /// The caller's grants on `repository`, when the authorizer could
    /// enumerate them at session start. `None` means per-action checks fall
    /// back to the authorizer with `token`.
    pub grants: Option<Grants>,
    /// The verified token the session was authorized with. `None` on a
    /// server with no verifier configured. Shared: the dispatch clones it per
    /// command, so the clone must stay a refcount bump.
    pub token: Option<Arc<VerifiedTokenOwned>>,
    /// Source repositories a cross-partition copy has already cleared with
    /// `token`. A repeated copy from the same source consults this set
    /// instead of re-asking the authorizer, which for the online authorizer
    /// spares a `CheckUserPermission` round trip per copy. Scoped to the
    /// session, so does not leak permissions for a shared Connection.
    pub authorized_sources: Arc<DashSet<RepositoryId>>,
}

impl SessionEntry {
    /// Whether the session's caller may perform `action` on the session's
    /// repository — the per-operation check for an action-gated storage
    /// command. Same contract as `RepositoryAuthorizer::permits`: answered
    /// from the grants enumerated at session start, asked of the authorizer
    /// when they were not enumerable, and without a verified token nothing
    /// is granted.
    pub async fn permits(&self, authorizer: &dyn RepositoryAuthorizer, action: &str) -> bool {
        if let Some(grants) = &self.grants {
            return grants.permits(action);
        }
        let Some(token) = &self.token else {
            return false;
        };
        authorizer
            .check_repository_access(Some(&token.as_token()), self.repository, Some(action))
            .await
            .is_ok()
    }
}

/// Per-connection session state for the `lore-storage/0.4` protocol.
///
/// Tracks active sessions mapping session IDs to repository, correlation ID, and user ID tuples.
/// Each `start()` always allocates a new session ID — deduplication is handled client-side by
/// `StorageConnector`. Copy-source authorization is cached per session
/// ([`SessionEntry::authorized_sources`]), not per connection.
///
/// The ID comes from [`NEXT_SESSION_ID`], one sequence for the whole process, so no two maps in
/// this process issue the same number and an ID this map did not issue resolves to nothing here.
/// See that constant for the two cases where that stops being true.
#[lore_macro::test_pub]
#[derive(Default)]
pub struct SessionMap {
    entries: DashMap<u32, SessionEntry>,
    /// Admission slots claimed before allocation. Unlike `DashMap::len` followed by insert, the
    /// compare-and-swap makes the limit one atomic decision across concurrent starts.
    active_sessions: AtomicU32,
}

#[derive(Debug, PartialEq)]
pub enum SessionError {
    LimitReached,
    CounterExhausted,
    NotFound,
}

impl SessionMap {
    /// The next id in the process-wide sequence that is free in `entries`, skipping 0.
    ///
    /// Zero is the wire's "no session" value, carried by every command sent before a session
    /// exists, so it can never name one.
    ///
    /// The sequence wraps after 2^32 allocations in a single server process. Wrapping is survived
    /// rather than prevented — refusing every further session would take the server down to avoid
    /// a rare collision — but it is survived by *checking*, not by hoping. Inserting a wrapped id
    /// blindly would replace a live entry in this very map, and the client's generation check
    /// gives no cover there: the client's id genuinely is current, and it is the server that
    /// reassigned the number underneath it. So the entry is claimed through the vacant-entry API,
    /// and an occupied one costs another draw.
    ///
    /// Bounded, because an unbounded search under a full map would spin: the map holds at most
    /// [`MAX_CONCURRENT_SESSIONS`] entries out of 2^32 ids, so a handful of draws finding every
    /// one of them occupied means something is wrong that a longer loop will not fix.
    /// `entry` is inserted under the id this returns, inside the same vacant-entry claim, so no
    /// concurrent `start` can be handed the same number between the check and the insert.
    /// Allocate against an arbitrary sequence.
    ///
    /// Split out for one reason: [`NEXT_SESSION_ID`] is a process-wide `static`, and a test that
    /// reset it would corrupt every other test drawing from it in the same binary. Passing the
    /// sequence in lets a test seed its own at `u32::MAX` to drive the wrap and the zero skip, or
    /// pre-fill the map to drive the redraw and [`SessionError::CounterExhausted`] — the paths
    /// that stop a wrapped id from replacing a live session, and which would otherwise ship
    /// unexercised.
    #[lore_macro::test_pub]
    fn allocate_from(
        &self,
        sequence: &AtomicU32,
        entry: SessionEntry,
    ) -> Result<u32, SessionError> {
        const DRAWS: usize = 8;
        for _ in 0..DRAWS {
            let id = sequence.fetch_add(1, Ordering::Relaxed);
            if id == 0 {
                continue;
            }
            #[expect(
                clippy::disallowed_methods,
                reason = "synchronous entry claim; nothing awaits while the shard lock is held"
            )]
            let vacancy = self.entries.entry(id);
            if let dashmap::mapref::entry::Entry::Vacant(vacant) = vacancy {
                vacant.insert(entry);
                return Ok(id);
            }
        }
        Err(SessionError::CounterExhausted)
    }

    /// Start a new session. Always allocates a fresh session ID — deduplication
    /// is the client's responsibility (`StorageConnector`).
    pub fn start(
        &self,
        repository: RepositoryId,
        correlation_id: String,
        user_id: String,
        permissions: Vec<String>,
        grants: Option<Grants>,
        token: Option<Arc<VerifiedTokenOwned>>,
    ) -> Result<(u32, String), SessionError> {
        self.start_from(
            &NEXT_SESSION_ID,
            repository,
            correlation_id,
            user_id,
            permissions,
            grants,
            token,
        )
    }

    /// [`SessionMap::start`] against an arbitrary sequence for deterministic allocation tests.
    #[lore_macro::test_pub]
    #[expect(
        clippy::too_many_arguments,
        reason = "start's arguments plus the injected sequence; a struct would exist only for tests"
    )]
    fn start_from(
        &self,
        sequence: &AtomicU32,
        repository: RepositoryId,
        correlation_id: String,
        user_id: String,
        permissions: Vec<String>,
        grants: Option<Grants>,
        token: Option<Arc<VerifiedTokenOwned>>,
    ) -> Result<(u32, String), SessionError> {
        self.active_sessions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_CONCURRENT_SESSIONS).then_some(active + 1)
            })
            .map_err(|_err| SessionError::LimitReached)?;

        let correlation_id = if correlation_id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            correlation_id
        };

        let session_id = match self.allocate_from(
            sequence,
            SessionEntry {
                repository,
                correlation_id: correlation_id.clone(),
                user_id,
                permissions,
                grants,
                token,
                authorized_sources: Arc::new(DashSet::new()),
            },
        ) {
            Ok(session_id) => session_id,
            Err(error) => {
                self.active_sessions.fetch_sub(1, Ordering::Release);
                return Err(error);
            }
        };

        Ok((session_id, correlation_id))
    }

    /// Stop an active session.
    pub fn stop(&self, session_id: u32) -> Result<(), SessionError> {
        match self.entries.remove(&session_id) {
            Some(_) => {
                self.active_sessions.fetch_sub(1, Ordering::Release);
                Ok(())
            }
            None => Err(SessionError::NotFound),
        }
    }

    pub fn get(&self, session_id: u32) -> Option<dashmap::mapref::one::Ref<'_, u32, SessionEntry>> {
        self.entries.get(&session_id)
    }
}

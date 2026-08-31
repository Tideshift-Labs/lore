// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::LazyLock;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use dashmap::DashMap;
use dashmap::DashSet;
use lore_revision::lore::RepositoryId;

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
/// process are roughly that process's live session count over 2^32 — with
/// [`MAX_CONCURRENT_SESSIONS`] that is about one in two million per attempt, not one in four
/// billion. Small, and not a guarantee.
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
    /// per-request token, so write-permission enforcement reads this.
    pub permissions: Vec<String>,
}

/// Per-connection session state for the `lore-storage/0.4` protocol.
///
/// Tracks active sessions mapping session IDs to repository, correlation ID, and user ID tuples,
/// with a set of authorized repositories for Copy checks. Each `start()` always allocates a new
/// session ID — deduplication is handled client-side by `StorageConnector`.
///
/// The ID comes from [`NEXT_SESSION_ID`], one sequence for the whole process, so no two maps in
/// this process issue the same number and an ID this map did not issue resolves to nothing here.
/// See that constant for the two cases where that stops being true.
#[derive(Default)]
pub struct SessionMap {
    entries: DashMap<u32, SessionEntry>,
    authorized_repos: DashSet<RepositoryId>,
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
    fn allocate(&self, entry: SessionEntry) -> Result<u32, SessionError> {
        self.allocate_from(&NEXT_SESSION_ID, entry)
    }

    /// [`SessionMap::allocate`] against an arbitrary sequence.
    ///
    /// Split out for one reason: [`NEXT_SESSION_ID`] is a process-wide `static`, and a test that
    /// reset it would corrupt every other test drawing from it in the same binary. Passing the
    /// sequence in lets a test seed its own at `u32::MAX` to drive the wrap and the zero skip, or
    /// pre-fill the map to drive the redraw and [`SessionError::CounterExhausted`] — the paths
    /// that stop a wrapped id from replacing a live session, and which would otherwise ship
    /// unexercised.
    fn allocate_from(
        &self,
        sequence: &AtomicU32,
        entry: SessionEntry,
    ) -> Result<u32, SessionError> {
        const DRAWS: usize = 8;
        let mut entry = Some(entry);
        for _ in 0..DRAWS {
            let id = sequence.fetch_add(1, Ordering::Relaxed);
            if id == 0 {
                continue;
            }
            #[allow(clippy::disallowed_methods)]
            // Synchronous entry check; nothing awaits while the shard lock is held.
            let vacancy = self.entries.entry(id);
            if let dashmap::mapref::entry::Entry::Vacant(vacant) = vacancy {
                let Some(entry) = entry.take() else {
                    return Err(SessionError::CounterExhausted);
                };
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
    ) -> Result<(u32, String), SessionError> {
        if self.entries.len() >= MAX_CONCURRENT_SESSIONS as usize {
            return Err(SessionError::LimitReached);
        }

        let correlation_id = if correlation_id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            correlation_id
        };

        // Allocated before the repository is authorized, so a failure to allocate leaves nothing
        // behind. Authorizing first would add the repository to this connection's Copy-source
        // scope for a session that then failed to exist.
        let session_id = self.allocate(SessionEntry {
            repository,
            correlation_id: correlation_id.clone(),
            user_id,
            permissions,
        })?;

        self.authorized_repos.insert(repository);

        Ok((session_id, correlation_id))
    }

    /// Stop an active session. The repository remains in the authorized set
    /// for Copy source-repo checks.
    pub fn stop(&self, session_id: u32) -> Result<(), SessionError> {
        match self.entries.remove(&session_id) {
            Some(_) => Ok(()),
            None => Err(SessionError::NotFound),
        }
    }

    pub fn get(&self, session_id: u32) -> Option<dashmap::mapref::one::Ref<'_, u32, SessionEntry>> {
        self.entries.get(&session_id)
    }

    /// O(1) check whether a repository has been authorized on this connection
    /// (i.e. had at least one session started for it).
    pub fn is_repository_authorized(&self, repository: RepositoryId) -> bool {
        self.authorized_repos.contains(&repository)
    }
}

#[cfg(test)]
mod tests {
    use rand::random;

    use super::*;

    #[test]
    fn start_returns_a_nonzero_id() {
        let map = SessionMap::default();
        let (id, _) = map
            .start(random(), "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        // A weaker claim than the name this test used to have
        // (`start_never_assigns_the_reserved_zero_id`): with `NEXT_SESSION_ID` randomly seeded,
        // this alone passes with probability ~1 whether or not the zero skip in `allocate_from`
        // exists at all. `allocate_from_skips_a_drawn_zero_id_and_retries` below is the actual
        // pin for that skip; this one stays as a cheap, honestly-named sanity check.
        assert_ne!(id, 0, "0 is the wire's 'no session' value and names none");
    }

    /// The actual zero-skip pin, using [`SessionMap::allocate_from`] to drive a local sequence
    /// right up to its wrap point deterministically -- resetting the real process-wide
    /// [`NEXT_SESSION_ID`] would corrupt every other test drawing from it in this binary.
    #[test]
    fn allocate_from_skips_a_drawn_zero_id_and_retries() {
        let map = SessionMap::default();
        let sequence = AtomicU32::new(u32::MAX);

        let first = map
            .allocate_from(
                &sequence,
                SessionEntry {
                    repository: random(),
                    correlation_id: "first".into(),
                    user_id: String::new(),
                    permissions: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(
            first,
            u32::MAX,
            "the draw right before the wrap must still return its own (nonzero) value"
        );

        // The sequence's internal counter is now 0 (u32::MAX + 1 wrapped). The very next draw
        // would be exactly the reserved zero id if the skip did not exist.
        let second = map
            .allocate_from(
                &sequence,
                SessionEntry {
                    repository: random(),
                    correlation_id: "second".into(),
                    user_id: String::new(),
                    permissions: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(
            second, 1,
            "a draw landing on the wrapped zero id must be skipped and retried, landing on 1"
        );
    }

    /// The redraw-on-collision pin (INV-EO-adjacent): after a wrap, a reused number must not
    /// silently replace a live session already in THIS map. The client-side generation check
    /// gives no cover here -- the client's id is genuinely current, and it is the server that
    /// reassigned the number underneath it.
    #[test]
    fn allocate_from_redraws_past_a_collision_and_leaves_the_occupant_untouched() {
        let map = SessionMap::default();
        let sequence = AtomicU32::new(100);
        let occupant_repository = random::<RepositoryId>();

        // Occupy the id the next draw would produce, exactly as a live session already would.
        map.entries.insert(
            100,
            SessionEntry {
                repository: occupant_repository,
                correlation_id: "occupant".into(),
                user_id: "occupant-user".into(),
                permissions: vec!["read".into()],
            },
        );

        let new_repository = random::<RepositoryId>();
        let allocated = map
            .allocate_from(
                &sequence,
                SessionEntry {
                    repository: new_repository,
                    correlation_id: "new".into(),
                    user_id: String::new(),
                    permissions: Vec::new(),
                },
            )
            .unwrap();

        assert_eq!(
            allocated, 101,
            "a collision on the first draw must redraw to the next id, not overwrite the \
             occupied one"
        );
        let occupant = map
            .get(100)
            .expect("the pre-existing occupant must survive the redraw");
        assert_eq!(
            occupant.repository, occupant_repository,
            "the occupant's own fields must be exactly what was there before -- not silently \
             replaced by the new allocation"
        );
        assert_eq!(occupant.correlation_id, "occupant");
    }

    /// [`SessionError::CounterExhausted`] when every one of the bounded draws collides. This is
    /// what stands between a wrapped id and silently overwriting a live session once redrawing
    /// itself is exhausted: refuse the allocation rather than fall through to an insert.
    #[test]
    fn allocate_from_exhausts_after_eight_consecutive_collisions() {
        let map = SessionMap::default();
        let sequence = AtomicU32::new(500);
        for id in 500..508 {
            map.entries.insert(
                id,
                SessionEntry {
                    repository: random(),
                    correlation_id: format!("occupant-{id}"),
                    user_id: String::new(),
                    permissions: Vec::new(),
                },
            );
        }

        let result = map.allocate_from(
            &sequence,
            SessionEntry {
                repository: random(),
                correlation_id: "never-inserted".into(),
                user_id: String::new(),
                permissions: Vec::new(),
            },
        );

        assert_eq!(result, Err(SessionError::CounterExhausted));
        for id in 500..508 {
            assert_eq!(
                map.get(id)
                    .expect("every pre-filled occupant must survive")
                    .correlation_id,
                format!("occupant-{id}"),
                "no pre-existing occupant may be overwritten by the exhausted allocation attempt"
            );
        }
    }

    /// Advances, but no assertion on *by how much*: the sequence is process-wide and every other
    /// test in this binary draws from it concurrently, so `id1 + 1` would be a flake, not a pin.
    #[test]
    fn start_advances_the_session_id() {
        let map = SessionMap::default();
        let repo = random::<RepositoryId>();
        let (id1, _) = map
            .start(repo, "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        let (id2, _) = map
            .start(repo, "corr-2".into(), String::new(), Vec::new())
            .unwrap();
        assert_ne!(id1, id2);
    }

    /// The INV-EO P0 pin. Two maps are two accepted connections; an id issued by one must not
    /// resolve in the other, or a command carrying it executes under the wrong session's
    /// repository and permissions.
    #[test]
    fn two_maps_never_issue_the_same_session_id() {
        let first = SessionMap::default();
        let second = SessionMap::default();
        let repo = random::<RepositoryId>();

        let (id1, _) = first
            .start(repo, "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        let (id2, _) = second
            .start(random(), "corr-2".into(), String::new(), Vec::new())
            .unwrap();

        assert_ne!(id1, id2);
        assert!(
            second.get(id1).is_none(),
            "an id issued by another connection's map must resolve to nothing here"
        );
        assert_eq!(second.stop(id1), Err(SessionError::NotFound));
        assert!(
            second.get(id2).is_some(),
            "the stale stop must not have removed this map's own live session"
        );
    }

    #[test]
    fn start_always_allocates_new_id() {
        let map = SessionMap::default();
        let repo = random::<RepositoryId>();
        let (id1, _) = map
            .start(repo, "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        let (id2, _) = map
            .start(repo, "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn start_empty_correlation_generates_uuid() {
        let map = SessionMap::default();
        let repo = random::<RepositoryId>();
        let (id1, corr1) = map
            .start(repo, String::new(), String::new(), Vec::new())
            .unwrap();
        let (id2, corr2) = map
            .start(repo, String::new(), String::new(), Vec::new())
            .unwrap();
        assert_ne!(id1, id2);
        assert!(!corr1.is_empty());
        assert!(!corr2.is_empty());
        assert_ne!(corr1, corr2);
    }

    #[test]
    fn stop_removes_session() {
        let map = SessionMap::default();
        let repo = random::<RepositoryId>();
        let (id, _) = map
            .start(repo, "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        assert!(map.get(id).is_some());
        map.stop(id).unwrap();
        assert!(map.get(id).is_none());
    }

    #[test]
    fn stop_unknown_returns_not_found() {
        let map = SessionMap::default();
        assert_eq!(map.stop(999), Err(SessionError::NotFound));
    }

    #[test]
    fn stop_already_stopped_returns_not_found() {
        let map = SessionMap::default();
        let (id, _) = map
            .start(random(), "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        map.stop(id).unwrap();
        assert_eq!(map.stop(id), Err(SessionError::NotFound));
    }

    #[test]
    fn start_after_stop_allocates_new_id() {
        let map = SessionMap::default();
        let repo = random::<RepositoryId>();
        let (id1, _) = map
            .start(repo, "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        map.stop(id1).unwrap();
        let (id2, _) = map
            .start(repo, "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn get_returns_entry_with_user_id() {
        let map = SessionMap::default();
        let repo = random::<RepositoryId>();
        let (id, _) = map
            .start(
                repo,
                "corr-1".into(),
                "user-42".into(),
                vec!["read".into(), "write".into()],
            )
            .unwrap();
        let entry = map.get(id).unwrap();
        assert_eq!(entry.repository, repo);
        assert_eq!(entry.correlation_id, "corr-1");
        assert_eq!(entry.user_id, "user-42");
        assert_eq!(entry.permissions, vec!["read", "write"]);
    }

    #[test]
    fn get_returns_none_for_unknown() {
        let map = SessionMap::default();
        assert!(map.get(42).is_none());
    }

    #[test]
    fn is_repository_authorized() {
        let map = SessionMap::default();
        let repo_a = random::<RepositoryId>();
        let repo_b = random::<RepositoryId>();
        map.start(repo_a, "corr-1".into(), String::new(), Vec::new())
            .unwrap();

        assert!(map.is_repository_authorized(repo_a));
        assert!(!map.is_repository_authorized(repo_b));
    }

    #[test]
    fn stop_does_not_remove_authorized_repo() {
        let map = SessionMap::default();
        let repo = random::<RepositoryId>();
        let (id, _) = map
            .start(repo, "corr-1".into(), String::new(), Vec::new())
            .unwrap();
        map.stop(id).unwrap();
        assert!(map.is_repository_authorized(repo));
    }

    #[test]
    fn concurrent_session_limit() {
        let map = SessionMap::default();
        let repo = random::<RepositoryId>();
        for i in 0..MAX_CONCURRENT_SESSIONS {
            map.start(repo, format!("corr-{i}"), String::new(), Vec::new())
                .unwrap();
        }
        assert_eq!(
            map.start(repo, "one-more".into(), String::new(), Vec::new()),
            Err(SessionError::LimitReached)
        );
    }

    #[test]
    fn limit_freed_by_stop() {
        let map = SessionMap::default();
        let repo = random::<RepositoryId>();
        let mut ids = Vec::new();
        for i in 0..MAX_CONCURRENT_SESSIONS {
            let (id, _) = map
                .start(repo, format!("corr-{i}"), String::new(), Vec::new())
                .unwrap();
            ids.push(id);
        }
        assert_eq!(
            map.start(repo, "blocked".into(), String::new(), Vec::new()),
            Err(SessionError::LimitReached)
        );
        map.stop(ids[0]).unwrap();
        map.start(repo, "freed".into(), String::new(), Vec::new())
            .unwrap();
    }
}

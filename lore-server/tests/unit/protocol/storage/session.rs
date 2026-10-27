// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use dashmap::DashSet;
use lore_revision::lore::RepositoryId;
use lore_server::authnz::repository_authorizer::Grants;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::VerifiedTokenOwned;
use lore_server::protocol::storage::session::*;
use rand::random;

/// A bare entry for the allocation tests, which only care about the fields they assert on.
fn bare_entry(repository: RepositoryId, correlation_id: &str, user_id: &str) -> SessionEntry {
    SessionEntry {
        repository,
        correlation_id: correlation_id.to_string(),
        user_id: user_id.to_string(),
        permissions: Vec::new(),
        grants: None,
        token: None,
        authorized_sources: Arc::new(DashSet::new()),
        declared: false,
    }
}

mod entry_permits {
    use std::collections::HashSet;

    use async_trait::async_trait;
    use lore_server::auth::jwt::AuthorizationToken;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::authnz::repository_authorizer::VerifiedToken;
    use tonic::Status;

    use super::*;

    /// Non-enumerable authorizer permitting exactly one action.
    struct PolicyOnly(&'static str);

    #[async_trait]
    impl RepositoryAuthorizer for PolicyOnly {
        async fn check_repository_access(
            &self,
            token: Option<&VerifiedToken<'_>>,
            _repository_id: RepositoryId,
            action: Option<&str>,
        ) -> Result<(), Status> {
            if token.is_some() && action == Some(self.0) {
                Ok(())
            } else {
                Err(Status::permission_denied("Not permitted"))
            }
        }
    }

    fn entry(grants: Option<Grants>, token: Option<Arc<VerifiedTokenOwned>>) -> SessionEntry {
        SessionEntry {
            repository: random(),
            correlation_id: "corr".to_string(),
            user_id: String::new(),
            permissions: Vec::new(),
            grants,
            token,
            authorized_sources: Arc::new(DashSet::new()),
            declared: false,
        }
    }

    fn owned_token() -> Arc<VerifiedTokenOwned> {
        Arc::new(VerifiedTokenOwned {
            raw: "raw.jwt".to_string(),
            claims: AuthorizationToken::default(),
        })
    }

    /// The grants stored at session start answer first — proven by
    /// pairing them with authorizers that would answer the opposite.
    #[tokio::test]
    async fn stored_grants_answer_before_the_authorizer() {
        let entry = entry(
            Some(Grants::Actions(HashSet::from(["migrate".to_string()]))),
            Some(owned_token()),
        );
        assert!(entry.permits(&PolicyOnly("other"), "migrate").await);
        assert!(
            !entry
                .permits(&AllowAllRepositoryAuthorizer, "obliterate")
                .await
        );
    }

    #[tokio::test]
    async fn non_enumerated_sessions_ask_the_authorizer_per_action() {
        let entry = entry(None, Some(owned_token()));
        assert!(entry.permits(&PolicyOnly("migrate"), "migrate").await);
        assert!(!entry.permits(&PolicyOnly("migrate"), "obliterate").await);
    }

    /// Without a verified token nothing is granted, whatever the
    /// authorizer would say — the contract `RepositoryAuthorizer::permits`
    /// keeps for request extensions.
    #[tokio::test]
    async fn no_token_grants_nothing_even_under_allow_all() {
        let entry = entry(None, None);
        assert!(
            !entry
                .permits(&AllowAllRepositoryAuthorizer, "migrate")
                .await
        );
    }
}

// FORK-LOCAL (INV-EO P0-1/P0-2): ids come from the process-wide, randomly seeded
// `NEXT_SESSION_ID`, so upstream's `start_assigns_session_id_from_one` and
// `start_increments_session_id` do not hold here. They are replaced by
// `start_returns_a_nonzero_id` and `start_advances_the_session_id`.

#[test]
fn start_returns_a_nonzero_id() {
    let map = SessionMap::default();
    let (id, _) = map
        .start(
            random(),
            "corr-1".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
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
/// `NEXT_SESSION_ID` would corrupt every other test drawing from it in this binary.
#[test]
fn allocate_from_skips_a_drawn_zero_id_and_retries() {
    let map = SessionMap::default();
    let sequence = AtomicU32::new(u32::MAX);

    let first = map
        .allocate_from(&sequence, bare_entry(random(), "first", ""))
        .unwrap();
    assert_eq!(
        first,
        u32::MAX,
        "the draw right before the wrap must still return its own (nonzero) value"
    );

    // The sequence's internal counter is now 0 (u32::MAX + 1 wrapped). The very next draw
    // would be exactly the reserved zero id if the skip did not exist.
    let second = map
        .allocate_from(&sequence, bare_entry(random(), "second", ""))
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
    let mut occupant = bare_entry(occupant_repository, "occupant", "occupant-user");
    occupant.permissions = vec!["read".into()];
    map.entries.insert(100, occupant);

    let new_repository = random::<RepositoryId>();
    let allocated = map
        .allocate_from(&sequence, bare_entry(new_repository, "new", ""))
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
        map.entries
            .insert(id, bare_entry(random(), &format!("occupant-{id}"), ""));
    }

    let result = map.allocate_from(&sequence, bare_entry(random(), "never-inserted", ""));

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
        .start(
            repo,
            "corr-1".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    let (id2, _) = map
        .start(
            repo,
            "corr-2".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
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
        .start(
            repo,
            "corr-1".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    let (id2, _) = second
        .start(
            random(),
            "corr-2".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
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
        .start(
            repo,
            "corr-1".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    let (id2, _) = map
        .start(
            repo,
            "corr-1".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn start_empty_correlation_generates_uuid() {
    let map = SessionMap::default();
    let repo = random::<RepositoryId>();
    let (id1, corr1) = map
        .start(
            repo,
            String::new(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    let (id2, corr2) = map
        .start(
            repo,
            String::new(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
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
        .start(
            repo,
            "corr-1".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    assert!(map.get(id).is_some());
    map.stop(id).unwrap();
    assert!(map.get(id).is_none());
}

#[test]
fn stop_unknown_returns_not_found() {
    let map = SessionMap::default();
    assert_eq!(map.stop(999), Err(SessionError::NotFound));
    assert_eq!(map.active_sessions.load(Ordering::Acquire), 0);
}

#[test]
fn stop_already_stopped_returns_not_found() {
    let map = SessionMap::default();
    let (id, _) = map
        .start(
            random(),
            "corr-1".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    map.stop(id).unwrap();
    assert_eq!(map.active_sessions.load(Ordering::Acquire), 0);
    assert_eq!(map.stop(id), Err(SessionError::NotFound));
    assert_eq!(
        map.active_sessions.load(Ordering::Acquire),
        0,
        "a second stop must not decrement the admission count below zero"
    );
}

#[test]
fn start_after_stop_allocates_new_id() {
    let map = SessionMap::default();
    let repo = random::<RepositoryId>();
    let (id1, _) = map
        .start(
            repo,
            "corr-1".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    map.stop(id1).unwrap();
    let (id2, _) = map
        .start(
            repo,
            "corr-1".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
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
            None,
            None,
            false,
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
fn concurrent_session_limit() {
    let map = SessionMap::default();
    let repo = random::<RepositoryId>();
    for i in 0..MAX_CONCURRENT_SESSIONS {
        map.start(
            repo,
            format!("corr-{i}"),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    }
    assert_eq!(
        map.start(
            repo,
            "one-more".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false
        ),
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
            .start(
                repo,
                format!("corr-{i}"),
                String::new(),
                Vec::new(),
                None,
                None,
                false,
            )
            .unwrap();
        ids.push(id);
    }
    assert_eq!(
        map.start(
            repo,
            "blocked".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false
        ),
        Err(SessionError::LimitReached)
    );
    map.stop(ids[0]).unwrap();
    map.start(
        repo,
        "freed".into(),
        String::new(),
        Vec::new(),
        None,
        None,
        false,
    )
    .unwrap();
}

/// A length check followed by insert lets every caller below the limit pass at once. Seed one
/// slot below the cap and release a group together: exactly one may claim the final slot.
#[test]
fn concurrent_starts_cannot_overbook_the_session_limit() {
    const CONTENDERS: usize = 32;
    let map = Arc::new(SessionMap::default());
    map.active_sessions
        .store(MAX_CONCURRENT_SESSIONS - 1, Ordering::Release);
    let barrier = Arc::new(Barrier::new(CONTENDERS));

    let successes = std::thread::scope(|scope| {
        let handles = (0..CONTENDERS)
            .map(|index| {
                let map = map.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    map.start(
                        random(),
                        format!("concurrent-{index}"),
                        String::new(),
                        Vec::new(),
                        None,
                        None,
                        false,
                    )
                    .is_ok()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|success| *success)
            .count()
    });

    assert_eq!(successes, 1, "only the final admission slot may be claimed");
    assert_eq!(
        map.active_sessions.load(Ordering::Acquire),
        MAX_CONCURRENT_SESSIONS
    );
}

#[test]
fn allocation_failure_refunds_the_claimed_session_slot() {
    const OCCUPIED: u32 = 8;
    let map = SessionMap::default();
    let sequence = AtomicU32::new(500);
    for id in 500..500 + OCCUPIED {
        map.entries
            .insert(id, bare_entry(random(), &format!("occupant-{id}"), ""));
    }
    map.active_sessions.store(OCCUPIED, Ordering::Release);

    let result = map.start_from(
        &sequence,
        random(),
        "must-fail".into(),
        String::new(),
        Vec::new(),
        None,
        None,
        false,
    );

    assert_eq!(result, Err(SessionError::CounterExhausted));
    assert_eq!(
        map.active_sessions.load(Ordering::Acquire),
        OCCUPIED,
        "failed allocation must refund the admission slot it claimed"
    );
}

/// WP-124: the declaration is fixed when the session starts, recorded per session, and does
/// not leak between two sessions of one map.
#[test]
fn start_records_the_declared_flag_per_session() {
    let map = SessionMap::default();
    let repo = random::<RepositoryId>();
    let (declared_id, _) = map
        .start(
            repo,
            "declared".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            true,
        )
        .unwrap();
    let (plain_id, _) = map
        .start(
            repo,
            "plain".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            false,
        )
        .unwrap();
    assert!(map.get(declared_id).unwrap().declared);
    assert!(!map.get(plain_id).unwrap().declared);
}

#[test]
fn start_from_records_the_declared_flag() {
    let map = SessionMap::default();
    let sequence = AtomicU32::new(900);
    let (id, _) = map
        .start_from(
            &sequence,
            random(),
            "declared".into(),
            String::new(),
            Vec::new(),
            None,
            None,
            true,
        )
        .unwrap();
    assert!(map.get(id).unwrap().declared);
}

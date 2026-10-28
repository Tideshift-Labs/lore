// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-124 slice 5b: the QUIC token-expiry re-check. [SERVER]
//!
//! A `lore-storage/0.4` session keeps the token it started with, so the server re-checks that
//! token's `exp` (plus the verifier's leeway) per command: an expired session is answered storage
//! status 201 before admission, the write gate, and any handler. `urc/0.2` has no session and
//! re-checks the connection's token the same way, answering `NotAuthorized`. Reads follow the one
//! switch `TOKEN_EXPIRY_GATES_READS`; every read expectation here derives from it, so flipping the
//! switch turns the assertions, not the suite, red or green.
//!
//! The harness (`Cmd`, `Stores`, `Service`) is the strict-admission one of the parent module: the
//! counting stores prove "no store effect". `Verify` is served from the uncounted local store, so
//! for it the proof is the early `SessionExpired` return itself.

use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::repository_authorizer::VerifiedTokenOwned;
use lore_server::protocol::storage::session::EXPIRED_SESSION_SWEEP_GRACE_SECS;
use lore_server::protocol::storage::session::MAX_CONCURRENT_SESSIONS;
use lore_server::protocol::storage::session::SessionEntry;
use lore_server::protocol::storage::session::SessionError;
use lore_server::protocol::storage::session::SessionMap;
use lore_server::protocol::storage::session::TOKEN_EXP_LEEWAY_SECS;
use lore_server::protocol::storage::session::TOKEN_EXPIRY_GATES_READS;
use lore_server::protocol::storage::session::now_unix_secs;
use lore_server::protocol::storage::session::token_expiry_gates;
use lore_transport::quic::STORAGE_SESSION_EXPIRED_STATUS;

use super::*;

// ---- clock helpers ------------------------------------------------------------------------

/// A token `exp` that is `secs` past `now + leeway`: the session started with it has been expired
/// for `secs` seconds (`expires_at = exp + leeway = now - secs`).
fn exp_expired_for(secs: u64) -> u64 {
    now_unix_secs().saturating_sub(secs + TOKEN_EXP_LEEWAY_SECS)
}

/// A token `exp` that is `secs` in the future.
fn exp_valid_for(secs: u64) -> u64 {
    now_unix_secs() + secs
}

fn token_with_exp(exp: u64) -> Arc<VerifiedTokenOwned> {
    Arc::new(VerifiedTokenOwned {
        raw: "raw.jwt".to_string(),
        claims: AuthorizationToken {
            user_id: "expiry-user".into(),
            expires: exp,
            ..Default::default()
        },
    })
}

/// A token expired for 60 s: past `exp + leeway`, well inside the sweep grace.
fn expired_exp() -> Option<u64> {
    Some(exp_expired_for(60))
}

// ---- v4 harness ---------------------------------------------------------------------------

/// A v4 service whose one seeded session carries a token with `exp` (`None` = no token at all).
fn v4_with_token(
    policy: CallerCapabilityPolicy,
    stores: &Stores,
    repository: RepositoryId,
    auth: bool,
    declared: bool,
    write: bool,
    exp: Option<u64>,
) -> Service {
    let verifier = if auth {
        verifier_present()
    } else {
        Arc::new(None)
    };
    let service = StorageServiceV4::new(
        verifier,
        Arc::new(AllowAllRepositoryAuthorizer),
        stores.immutable.clone(),
        stores.local.clone(),
        stores.mutable.clone(),
        auth,
        Arc::new(UserAgentFilter::default()),
    )
    .with_caller_capability_policy(policy);
    let permissions = if write {
        vec!["read".into(), "write".into()]
    } else {
        vec!["read".into()]
    };
    let (session_id, _) = service
        .session_map
        .start(
            repository,
            "corr".into(),
            "user".into(),
            permissions,
            None,
            exp.map(token_with_exp),
            declared,
        )
        .expect("seed session");
    Service::V4(service, session_id)
}

fn assert_session_expired(service: &Service, error: &MessageHandleError, case: &str) {
    assert!(
        matches!(error, MessageHandleError::SessionExpired),
        "{case}: expected SessionExpired, got {error:?}"
    );
    let (code, label, internal) = service.wire_code(error);
    assert_eq!(code, 201, "{case}: storage status");
    assert_eq!(code, STORAGE_SESSION_EXPIRED_STATUS, "{case}");
    for other in [
        QuicServiceError::ImplementationReserved,
        QuicServiceError::SlowDown,
        QuicServiceError::OutcomeUnknown,
        QuicServiceError::NotAuthorized,
        QuicServiceError::Failed,
    ] {
        assert_ne!(
            code, other as QuicErrorStatus,
            "{case}: 201 is its own code"
        );
    }
    assert_eq!(label, "SessionExpired", "{case}: metrics label");
    assert!(!internal, "{case}: a refusal is not an internal error");
}

/// Whether an expired session refuses `cmd`, derived from the one read switch.
fn refused_when_expired(cmd: Cmd) -> bool {
    MUTATIONS.contains(&cmd) || TOKEN_EXPIRY_GATES_READS
}

// ---- 1. the per-command gate --------------------------------------------------------------

#[test]
fn token_expiry_gates_classifies_every_request_variant() {
    let repository = random::<RepositoryId>();
    for v4 in [true, false] {
        for cmd in MUTATIONS {
            assert!(
                token_expiry_gates(&cmd.parsed(repository, v4)),
                "{cmd:?} (v4={v4}) is a mutation and is always gated"
            );
        }
        for cmd in READS {
            // Verify without heal is a read.
            assert_eq!(
                token_expiry_gates(&cmd.parsed(repository, v4)),
                TOKEN_EXPIRY_GATES_READS,
                "{cmd:?} (v4={v4}) follows the read switch"
            );
        }
    }
    let connect = parse_message_for_opcode(Command::Authorize as u8, Bytes::from(vec![0u8; 16]))
        .expect("Connect parses");
    assert!(matches!(connect, ParsedStorageRequest::Connect(_)));
    assert!(
        !token_expiry_gates(&connect),
        "Connect verifies a token of its own and is never gated"
    );
    let correlate = parse_message_for_opcode(5, Bytes::from_static(b"wp124-correlation-id"))
        .expect("Correlate parses");
    assert!(matches!(correlate, ParsedStorageRequest::Correlate(_)));
    assert_eq!(token_expiry_gates(&correlate), TOKEN_EXPIRY_GATES_READS);
}

#[tokio::test]
async fn an_expired_session_gets_201_for_every_mutation_with_no_store_call() {
    for cmd in MUTATIONS {
        let case = format!("{cmd:?}");
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        // Admitted and authorized on every other count: compatible policy, write grant, declared.
        let service = v4_with_token(
            COMPATIBLE,
            &stores,
            repository,
            true,
            true,
            true,
            expired_exp(),
        );
        let error = service
            .run(cmd, repository)
            .await
            .expect_err(&format!("{case}: an expired session must be refused"));
        assert_session_expired(&service, &error, &case);
        assert_eq!(
            stores.calls(),
            0,
            "{case}: a refused mutation touched a store"
        );
    }
}

#[tokio::test]
async fn an_expired_sessions_reads_follow_the_read_switch() {
    for cmd in READS {
        let case = format!("{cmd:?} (reads gated = {TOKEN_EXPIRY_GATES_READS})");
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        let service = v4_with_token(
            COMPATIBLE,
            &stores,
            repository,
            false,
            false,
            false,
            expired_exp(),
        );
        let result = service.run(cmd, repository).await;
        if refused_when_expired(cmd) {
            let error = result.expect_err(&format!("{case}: must be refused"));
            assert_session_expired(&service, &error, &case);
            assert_eq!(stores.calls(), 0, "{case}: a refused read touched a store");
        } else {
            assert!(
                !matches!(result, Err(MessageHandleError::SessionExpired)),
                "{case}: switch off, so reads stay open, got {result:?}"
            );
            if cmd.reaches_counted_store(Protocol::V4) {
                assert!(
                    stores.calls() > 0,
                    "{case}: an open read never reached the store"
                );
            }
        }
    }
}

/// The negative control for the two tests above: the same shapes with an unexpired token are
/// served, so the 201 is the expiry and nothing else. Inside the leeway counts as unexpired.
#[tokio::test]
async fn a_session_that_has_not_expired_is_unaffected() {
    let unexpired = [
        ("valid for an hour", Some(exp_valid_for(3600))),
        // `exp` itself has passed, but the verifier's leeway has not: still valid.
        (
            "past exp, inside the leeway",
            Some(now_unix_secs().saturating_sub(TOKEN_EXP_LEEWAY_SECS / 2)),
        ),
        ("no token (auth off)", None),
    ];
    for (name, exp) in unexpired {
        for cmd in MUTATIONS.into_iter().chain(READS) {
            let case = format!("{name} {cmd:?}");
            let stores = Stores::new().await;
            let repository = random::<RepositoryId>();
            let service = v4_with_token(COMPATIBLE, &stores, repository, false, false, false, exp);
            let result = service.run(cmd, repository).await;
            assert!(
                !matches!(result, Err(MessageHandleError::SessionExpired)),
                "{case}: must not be refused as expired, got {result:?}"
            );
            if cmd.reaches_counted_store(Protocol::V4) {
                assert!(stores.calls() > 0, "{case}: never reached the store");
            }
        }
    }
}

/// 201 is the first answer, ahead of caller admission (200) and the write gate. Each pair has an
/// unexpired positive control proving the other refusal really is in play for that shape.
#[tokio::test]
async fn expiry_is_answered_before_admission_and_the_write_gate() {
    for cmd in MUTATIONS {
        let case = format!("{cmd:?}");
        let repository = random::<RepositoryId>();

        // Strict policy, undeclared session: the other answer would be 200.
        let stores = Stores::new().await;
        let service = v4_with_token(
            STRICT,
            &stores,
            repository,
            false,
            false,
            false,
            expired_exp(),
        );
        let error = service.run(cmd, repository).await.expect_err(&case);
        assert_session_expired(&service, &error, &format!("{case} strict+undeclared"));
        assert_eq!(stores.calls(), 0, "{case}");
        let stores = Stores::new().await;
        let control = v4_with_token(
            STRICT,
            &stores,
            repository,
            false,
            false,
            false,
            Some(exp_valid_for(3600)),
        );
        let error = control.run(cmd, repository).await.expect_err(&case);
        assert_unsupported_client_on_the_wire(&control, &error, &format!("{case} control"));

        // Compatible policy, no write grant: the other answer would be NotAuthorized.
        let stores = Stores::new().await;
        let service = v4_with_token(
            COMPATIBLE,
            &stores,
            repository,
            true,
            false,
            false,
            expired_exp(),
        );
        let error = service.run(cmd, repository).await.expect_err(&case);
        assert_session_expired(&service, &error, &format!("{case} no write grant"));
        assert_eq!(stores.calls(), 0, "{case}");
        let stores = Stores::new().await;
        let control = v4_with_token(
            COMPATIBLE,
            &stores,
            repository,
            true,
            false,
            false,
            Some(exp_valid_for(3600)),
        );
        let error = control.run(cmd, repository).await.expect_err(&case);
        assert!(
            matches!(error, MessageHandleError::AuthorizationFailure(_)),
            "{case} control: expected the write gate, got {error:?}"
        );
        assert_eq!(stores.calls(), 0, "{case}");
    }
}

/// The refused entry is kept: every sibling in flight on the same id gets 201 too (the client
/// resends it after a rebind) instead of `NotConnected` (which it does not resend).
#[tokio::test]
async fn an_expired_session_stays_in_the_map_and_keeps_answering_201() {
    let stores = Stores::new().await;
    let repository = random::<RepositoryId>();
    let service = v4_with_token(
        COMPATIBLE,
        &stores,
        repository,
        true,
        true,
        true,
        expired_exp(),
    );
    let Service::V4(inner, session_id) = &service else {
        unreachable!("v4_with_token builds a v4 service");
    };
    for round in 0..3 {
        for cmd in [Cmd::Put, Cmd::MutableCas, Cmd::VerifyHeal] {
            let case = format!("round {round} {cmd:?}");
            let error = service.run(cmd, repository).await.expect_err(&case);
            assert_session_expired(&service, &error, &case);
        }
        assert!(
            inner.session_map.get(*session_id).is_some(),
            "round {round}: the refusal must not remove the entry"
        );
    }
}

/// `AuthorizeStop` is never gated: a client releases an expired session.
#[tokio::test]
async fn authorize_stop_still_stops_an_expired_session() {
    let stores = Stores::new().await;
    let repository = random::<RepositoryId>();
    let service = v4_with_token(
        COMPATIBLE,
        &stores,
        repository,
        true,
        true,
        true,
        expired_exp(),
    );
    let Service::V4(inner, session_id) = &service else {
        unreachable!("v4_with_token builds a v4 service");
    };
    let error = service
        .run(Cmd::Put, repository)
        .await
        .expect_err("expired");
    assert_session_expired(&service, &error, "before stop");

    inner
        .run_request_handler(
            AttributeMap::default().into(),
            ParsedStorageRequestV4::AuthorizeStop {
                session_id: *session_id,
            },
        )
        .await
        .expect("an expired session must still stop");
    assert!(inner.session_map.get(*session_id).is_none());
    let error = service
        .run(Cmd::Put, repository)
        .await
        .expect_err("stopped");
    assert!(
        matches!(error, MessageHandleError::NotConnected),
        "after the stop the id is gone, got {error:?}"
    );
}

/// Auth off (no verifier): `AuthorizeStart` stores no token, the session never expires, and
/// nothing is refused as expired however long it lives.
#[tokio::test]
async fn auth_off_sessions_never_expire() {
    let stores = Stores::new().await;
    let repository = random::<RepositoryId>();
    let service = StorageServiceV4::new(
        Arc::new(None),
        Arc::new(AllowAllRepositoryAuthorizer),
        stores.immutable.clone(),
        stores.local.clone(),
        stores.mutable.clone(),
        false,
        Arc::new(UserAgentFilter::default()),
    );
    let response = service
        .run_request_handler(
            AttributeMap::default().into(),
            ParsedStorageRequestV4::AuthorizeStart {
                repository,
                correlation_id: "corr".into(),
                auth_token: vec![],
                caller_capabilities: None,
            },
        )
        .await
        .expect("session opens with auth off");
    let session_id = u32::from_le_bytes(response[0][..4].try_into().unwrap());
    assert_eq!(
        service.session_map.get(session_id).unwrap().expires_at,
        None,
        "no token, no expiry"
    );
    assert!(
        !service
            .session_map
            .get(session_id)
            .unwrap()
            .is_expired_at(u64::MAX),
        "a token-less session is not expired at any time"
    );
    for cmd in MUTATIONS.into_iter().chain(READS) {
        let result = service
            .run_request_handler(
                AttributeMap::default().into(),
                ParsedStorageRequestV4::StorageCommand {
                    session_id,
                    opcode: cmd.opcode(),
                    payload: cmd.payload(repository, true),
                },
            )
            .await;
        assert!(
            !matches!(result, Err(MessageHandleError::SessionExpired)),
            "{cmd:?}: auth off, got {result:?}"
        );
    }
}

// ---- the entry's own clock ----------------------------------------------------------------

fn entry_expiring_at(expires_at: Option<u64>) -> SessionEntry {
    SessionEntry {
        repository: random(),
        correlation_id: "corr".into(),
        user_id: String::new(),
        permissions: Vec::new(),
        grants: None,
        token: None,
        authorized_sources: Arc::new(dashmap::DashSet::new()),
        declared: false,
        expires_at,
    }
}

/// jsonwebtoken's boundary is `exp + leeway < now`: the last valid second is `exp + leeway`.
#[test]
fn is_expired_at_is_strict_at_the_boundary() {
    let entry = entry_expiring_at(Some(1_000));
    assert!(!entry.is_expired_at(999), "before");
    assert!(
        !entry.is_expired_at(1_000),
        "expires_at == now is NOT expired"
    );
    assert!(
        entry.is_expired_at(1_001),
        "expires_at + 1 == now is expired"
    );
    assert!(!entry_expiring_at(None).is_expired_at(1_001));
    assert!(!entry_expiring_at(None).is_expired_at(u64::MAX));
}

#[test]
fn start_derives_expires_at_from_the_token_exp_plus_the_leeway() {
    let map = SessionMap::default();
    // start_from, not start: the real-clock sweep in start would remove the long-expired
    // fixtures as soon as the next one is started.
    let sequence = std::sync::atomic::AtomicU32::new(1);
    let start = |token: Option<Arc<VerifiedTokenOwned>>| {
        map.start_from(
            &sequence,
            random(),
            "corr".into(),
            String::new(),
            Vec::new(),
            None,
            token,
            false,
        )
        .expect("start")
        .0
    };
    let with_token = start(Some(token_with_exp(5_000)));
    let without_token = start(None);
    let saturating = start(Some(token_with_exp(u64::MAX)));
    assert_eq!(
        map.get(with_token).unwrap().expires_at,
        Some(5_000 + TOKEN_EXP_LEEWAY_SECS)
    );
    assert_eq!(map.get(without_token).unwrap().expires_at, None);
    assert_eq!(
        map.get(saturating).unwrap().expires_at,
        Some(u64::MAX),
        "an exp near u64::MAX must not wrap into the past"
    );
}

// ---- 2. the leeway constant ---------------------------------------------------------------

/// A session must expire at the instant `JwtVerifier` would refuse the same token on gRPC, so the
/// constant has to equal jsonwebtoken's default leeway, which `JwtVerifier` keeps.
#[test]
fn the_leeway_constant_equals_the_jsonwebtoken_default_the_verifier_keeps() {
    for algorithm in [
        jsonwebtoken::Algorithm::RS256,
        jsonwebtoken::Algorithm::ES256,
        jsonwebtoken::Algorithm::HS256,
    ] {
        assert_eq!(
            TOKEN_EXP_LEEWAY_SECS,
            jsonwebtoken::Validation::new(algorithm).leeway,
            "{algorithm:?}"
        );
    }
    // The verifier must not set its own leeway, or the equality above stops describing it.
    let source: String = include_str!("../../../../../src/auth/jwt.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        source.contains("Validation::new("),
        "the verifier builds its Validation with Validation::new"
    );
    assert!(
        !source.contains("leeway"),
        "JwtVerifier overrides the leeway; TOKEN_EXP_LEEWAY_SECS must follow it"
    );
}

// ---- wire mapping -------------------------------------------------------------------------

#[test]
fn session_expired_maps_to_201_not_logged_and_unauthenticated_on_grpc() {
    let error = MessageHandleError::SessionExpired;
    assert_eq!(STORAGE_SESSION_EXPIRED_STATUS, 201);
    assert!(!lore_server::quic::storage_service::is_internal_error(
        &error
    ));
    assert_eq!(
        lore_server::quic::storage_service::message_handle_error_to_label(&error),
        "SessionExpired"
    );
    // gRPC checks the token per call and never produces it; the arm only has to be sane.
    let status = lore_server::grpc::map_message_handle_error_to_status(&error, None, None);
    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    // The v4 service answers 201 and keeps it out of the error log (an expected, retried answer).
    let stores_service = StorageServiceV4::new(
        Arc::new(None),
        Arc::new(AllowAllRepositoryAuthorizer),
        Arc::new(NullImmutable),
        Arc::new(NullImmutable),
        Arc::new(NullMutable),
        false,
        Arc::new(UserAgentFilter::default()),
    );
    let info = stores_service.transform_protocol_error(&error);
    assert_eq!(info.response_error_code, 201);
    assert!(!info.is_appropriate_for_logging);
    assert!(!info.is_internal_error);
    // Positive control: another refusal is still logged-worthy, so the flag discriminates.
    let other = stores_service.transform_protocol_error(&MessageHandleError::NotConnected);
    assert_ne!(other.response_error_code, 201);
}

/// Stores for tests that never call them.
struct NullImmutable;
struct NullMutable;

#[async_trait]
impl ImmutableStore for NullImmutable {
    async fn get(
        self: Arc<Self>,
        _partition: Partition,
        _address: Address,
    ) -> Result<StoreGetData, StoreError> {
        unreachable!("never called")
    }
    async fn query(
        self: Arc<Self>,
        _partition: Partition,
        _addresses: &[Address],
        _results: &mut [StoreMatchResult],
    ) -> Result<(), StoreError> {
        unreachable!("never called")
    }
    async fn get_metadata(
        self: Arc<Self>,
        _partition: Partition,
        _address: Address,
    ) -> Result<StoreGetData, StoreError> {
        unreachable!("never called")
    }
    async fn put(
        self: Arc<Self>,
        _partition: Partition,
        _address: Address,
        _fragment: Fragment,
        _payload: Option<Bytes>,
        _force: bool,
    ) -> Result<(), StoreError> {
        unreachable!("never called")
    }
    async fn obliterate(
        self: Arc<Self>,
        _partition: Partition,
        _address: Address,
        _stats: Arc<StoreObliterateStats>,
    ) -> Result<(), StoreError> {
        unreachable!("never called")
    }
    async fn evict(
        self: Arc<Self>,
        _max_capacity: usize,
        _sync_data: bool,
        _sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<usize, StoreError> {
        unreachable!("never called")
    }
    async fn compact(
        self: Arc<Self>,
        _max_size: usize,
        _at: Option<usize>,
        _sync_data: bool,
        _sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<Option<usize>, StoreError> {
        unreachable!("never called")
    }
    async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
        None
    }
    fn max_query_batch(&self) -> Option<usize> {
        None
    }
    async fn flush(self: Arc<Self>, _sync_data: bool) -> Result<(), StoreError> {
        unreachable!("never called")
    }
    async fn verify(self: Arc<Self>, _heal: bool) -> Result<(), StoreError> {
        unreachable!("never called")
    }
    async fn copy(
        self: Arc<Self>,
        _source_partition: Partition,
        _source_address: Address,
        _destination_partition: Partition,
        _destination_context: Context,
        _behavior: CopyBehavior,
    ) -> Result<(), StoreError> {
        unreachable!("never called")
    }
}

#[async_trait]
impl MutableStore for NullMutable {
    async fn load(
        self: Arc<Self>,
        _partition: Partition,
        _key: Hash,
        _key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        unreachable!("never called")
    }
    async fn store(
        self: Arc<Self>,
        _partition: Partition,
        _key: Hash,
        _value: Hash,
        _key_type: KeyType,
    ) -> Result<(), StoreError> {
        unreachable!("never called")
    }
    async fn compare_and_swap(
        self: Arc<Self>,
        _partition: Partition,
        _key: Hash,
        _expected: Hash,
        _value: Hash,
        _key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        unreachable!("never called")
    }
    async fn list(
        self: Arc<Self>,
        _partition: Partition,
        _key_type: KeyType,
    ) -> Result<KeyValueStream, StoreError> {
        unreachable!("never called")
    }
    async fn flush(self: Arc<Self>, _sync_data: bool) -> Result<(), StoreError> {
        unreachable!("never called")
    }
}

// ---- 3. the sweep -------------------------------------------------------------------------

mod sweep {
    use std::sync::atomic::AtomicU32;

    use super::*;

    /// A fixed "now" for `sweep_expired`, so the boundaries are exact.
    const NOW: u64 = 1_000_000;

    fn start_expiring_at(map: &SessionMap, sequence: &AtomicU32, expires_at: Option<u64>) -> u32 {
        map.start_from(
            sequence,
            random(),
            "corr".into(),
            String::new(),
            Vec::new(),
            None,
            expires_at.map(|at| token_with_exp(at - TOKEN_EXP_LEEWAY_SECS)),
            false,
        )
        .expect("start")
        .0
    }

    #[test]
    fn removes_only_entries_expired_by_more_than_the_grace_and_frees_their_slots() {
        let map = SessionMap::default();
        let sequence = AtomicU32::new(10);
        let grace = EXPIRED_SESSION_SWEEP_GRACE_SECS;
        let long_expired = start_expiring_at(&map, &sequence, Some(NOW - grace - 1));
        let also_long_expired = start_expiring_at(&map, &sequence, Some(NOW - 10_000));
        let at_the_grace_edge = start_expiring_at(&map, &sequence, Some(NOW - grace));
        let inside_grace = start_expiring_at(&map, &sequence, Some(NOW - 100));
        let just_expired = start_expiring_at(&map, &sequence, Some(NOW - 1));
        let unexpired = start_expiring_at(&map, &sequence, Some(NOW + 100));
        let token_less = start_expiring_at(&map, &sequence, None);
        assert_eq!(map.active_sessions.load(Ordering::Acquire), 7);

        let removed = map.sweep_expired(NOW);

        assert_eq!(removed, 2, "exactly the two entries past the grace");
        assert!(map.get(long_expired).is_none());
        assert!(map.get(also_long_expired).is_none());
        for (name, id) in [
            (
                "grace edge (expired for exactly the grace)",
                at_the_grace_edge,
            ),
            ("inside the grace", inside_grace),
            ("just expired", just_expired),
            ("unexpired", unexpired),
            ("token-less", token_less),
        ] {
            assert!(map.get(id).is_some(), "{name} must stay");
        }
        assert_eq!(
            map.active_sessions.load(Ordering::Acquire),
            5,
            "the swept entries' admission slots are freed"
        );
        // Idempotent: nothing more to remove, and no double refund.
        assert_eq!(map.sweep_expired(NOW), 0);
        assert_eq!(map.active_sessions.load(Ordering::Acquire), 5);
        // One second later the grace edge entry is past it.
        assert_eq!(map.sweep_expired(NOW + 1), 1);
        assert!(map.get(at_the_grace_edge).is_none());
        assert_eq!(map.active_sessions.load(Ordering::Acquire), 4);
    }

    #[test]
    fn a_sweep_with_a_clock_before_the_grace_removes_nothing() {
        let map = SessionMap::default();
        let sequence = AtomicU32::new(10);
        start_expiring_at(&map, &sequence, Some(100));
        assert_eq!(map.sweep_expired(0), 0, "now < grace must not underflow");
        assert_eq!(map.sweep_expired(EXPIRED_SESSION_SWEEP_GRACE_SECS), 0);
    }

    /// Through the real clock and the real `start`: a session expired inside the grace survives
    /// the next start and still answers 201; one expired past it is gone by then.
    #[tokio::test]
    async fn start_sweeps_with_the_real_clock_and_honours_the_grace() {
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        let service = v4_with_token(
            COMPATIBLE,
            &stores,
            repository,
            true,
            true,
            true,
            expired_exp(),
        );
        let Service::V4(inner, in_grace) = &service else {
            unreachable!("v4_with_token builds a v4 service");
        };
        let long_gone = inner
            .session_map
            .start(
                repository,
                "old".into(),
                "user".into(),
                vec!["read".into(), "write".into()],
                None,
                Some(token_with_exp(exp_expired_for(
                    EXPIRED_SESSION_SWEEP_GRACE_SECS + 600,
                ))),
                true,
            )
            .expect("start")
            .0;
        assert!(inner.session_map.get(long_gone).is_some());

        // Any later start sweeps.
        let fresh = inner
            .session_map
            .start(
                repository,
                "fresh".into(),
                "user".into(),
                vec!["read".into(), "write".into()],
                None,
                Some(token_with_exp(exp_valid_for(3600))),
                true,
            )
            .expect("start")
            .0;

        assert!(inner.session_map.get(long_gone).is_none(), "swept");
        assert!(inner.session_map.get(fresh).is_some());
        assert!(inner.session_map.get(*in_grace).is_some(), "kept");
        let error = service
            .run(Cmd::Put, repository)
            .await
            .expect_err("expired");
        assert_session_expired(&service, &error, "inside the grace");
        let error = inner
            .run_request_handler(
                AttributeMap::default().into(),
                ParsedStorageRequestV4::StorageCommand {
                    session_id: long_gone,
                    opcode: Cmd::Put.opcode(),
                    payload: Cmd::Put.payload(repository, true),
                },
            )
            .await
            .expect_err("swept");
        assert!(
            matches!(error, MessageHandleError::NotConnected),
            "{error:?}"
        );
    }

    /// Superseded sessions must not grow toward `MAX_CONCURRENT_SESSIONS`: a client that rebinds
    /// at every token expiry and never stops the old id leaves one expired entry per cycle.
    #[test]
    fn repeated_start_and_expire_cycles_keep_the_active_count_bounded() {
        let map = SessionMap::default();
        let past_the_grace = exp_expired_for(EXPIRED_SESSION_SWEEP_GRACE_SECS + 600);
        let cycles = 500_u32;
        assert!(cycles < MAX_CONCURRENT_SESSIONS);
        for cycle in 1..=cycles {
            map.start(
                random(),
                format!("cycle-{cycle}"),
                String::new(),
                Vec::new(),
                None,
                Some(token_with_exp(past_the_grace)),
                false,
            )
            .expect("start");
            assert_eq!(
                map.active_sessions.load(Ordering::Acquire),
                1,
                "cycle {cycle}: the superseded entry is swept by the next start"
            );
        }
    }

    /// Without the sweep the same cycle count would be linear. Control: entries still inside the
    /// grace do accumulate, so the bound above is the sweep and not an artifact.
    #[test]
    fn entries_inside_the_grace_do_accumulate() {
        let map = SessionMap::default();
        let inside_grace = exp_expired_for(60);
        for cycle in 1..=50_u32 {
            map.start(
                random(),
                format!("cycle-{cycle}"),
                String::new(),
                Vec::new(),
                None,
                Some(token_with_exp(inside_grace)),
                false,
            )
            .expect("start");
        }
        assert_eq!(map.active_sessions.load(Ordering::Acquire), 50);
    }

    #[test]
    fn a_map_at_the_limit_with_old_expired_entries_admits_a_new_start() {
        let map = SessionMap::default();
        let sequence = AtomicU32::new(1);
        let long_expired = exp_expired_for(EXPIRED_SESSION_SWEEP_GRACE_SECS + 600);
        let old_entries = 100_u32;
        for _ in 0..old_entries {
            map.start_from(
                &sequence,
                random(),
                "old".into(),
                String::new(),
                Vec::new(),
                None,
                Some(token_with_exp(long_expired)),
                false,
            )
            .expect("fill");
        }
        for _ in old_entries..MAX_CONCURRENT_SESSIONS {
            map.start_from(
                &sequence,
                random(),
                "live".into(),
                String::new(),
                Vec::new(),
                None,
                None,
                false,
            )
            .expect("fill");
        }
        assert_eq!(
            map.active_sessions.load(Ordering::Acquire),
            MAX_CONCURRENT_SESSIONS
        );
        // Positive control: without a sweep the map is full.
        assert_eq!(
            map.start_from(
                &sequence,
                random(),
                "blocked".into(),
                String::new(),
                Vec::new(),
                None,
                None,
                false,
            ),
            Err(SessionError::LimitReached)
        );

        let admitted = map.start(
            random(),
            "admitted".into(),
            String::new(),
            Vec::new(),
            None,
            Some(token_with_exp(exp_valid_for(3600))),
            false,
        );
        assert!(
            admitted.is_ok(),
            "the sweep must free the old slots: {admitted:?}"
        );
        assert_eq!(
            map.active_sessions.load(Ordering::Acquire),
            MAX_CONCURRENT_SESSIONS - old_entries + 1
        );
    }

    #[test]
    fn a_map_full_of_live_and_in_grace_sessions_still_refuses() {
        let map = SessionMap::default();
        let sequence = AtomicU32::new(1);
        let inside_grace = exp_expired_for(60);
        for _ in 0..MAX_CONCURRENT_SESSIONS {
            map.start_from(
                &sequence,
                random(),
                "held".into(),
                String::new(),
                Vec::new(),
                None,
                Some(token_with_exp(inside_grace)),
                false,
            )
            .expect("fill");
        }
        assert_eq!(
            map.start(
                random(),
                "blocked".into(),
                String::new(),
                Vec::new(),
                None,
                None,
                false,
            ),
            Err(SessionError::LimitReached),
            "sessions inside the grace are not swept, so the limit still holds"
        );
    }

    /// A command on an id that was swept (expired by more than the grace, then a later start on
    /// the same map ran the sweep) is answered `NotConnected` (storage status 3), NOT 201: the
    /// entry is gone, so the server cannot tell the id was ever issued. A client only reaches
    /// this with an id it has already stopped using.
    #[tokio::test]
    async fn a_command_on_a_swept_id_is_not_connected_not_201() {
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        let service = v4_with_token(
            COMPATIBLE,
            &stores,
            repository,
            false,
            false,
            false,
            Some(exp_expired_for(EXPIRED_SESSION_SWEEP_GRACE_SECS + 600)),
        );
        let Service::V4(inner, swept) = &service else {
            unreachable!("v4_with_token builds a v4 service");
        };
        // Control: before any later start, the entry is still there and answers 201.
        let error = service
            .run(Cmd::Put, repository)
            .await
            .expect_err("expired");
        assert_session_expired(&service, &error, "before the sweep");

        inner
            .session_map
            .start(
                repository,
                "later".into(),
                String::new(),
                Vec::new(),
                None,
                None,
                false,
            )
            .expect("a later start runs the sweep");

        assert!(inner.session_map.get(*swept).is_none(), "swept");
        let error = service.run(Cmd::Put, repository).await.expect_err("swept");
        assert!(
            matches!(error, MessageHandleError::NotConnected),
            "{error:?}"
        );
        let (code, label, _) = service.wire_code(&error);
        assert_eq!(code, 3, "NotConnected answers storage status 3");
        assert_ne!(code, STORAGE_SESSION_EXPIRED_STATUS);
        assert_ne!(label, "SessionExpired");
        assert_eq!(stores.calls(), 0);
    }
}
// ---- 4. urc/0.2 ---------------------------------------------------------------------------

mod urc_0_2 {
    use super::*;

    fn token_claims(exp: u64) -> AuthorizationToken {
        AuthorizationToken {
            user_id: "expiry-user".into(),
            expires: exp,
            ..Default::default()
        }
    }

    fn legacy(
        policy: CallerCapabilityPolicy,
        stores: &Stores,
        verifier: bool,
        enforce: bool,
    ) -> StorageService {
        StorageService::new(
            if verifier {
                verifier_present()
            } else {
                Arc::new(None)
            },
            Arc::new(AllowAllRepositoryAuthorizer),
            stores.immutable.clone(),
            stores.local.clone(),
            stores.mutable.clone(),
            enforce,
        )
        .with_caller_capability_policy(policy)
    }

    fn connection(repository: RepositoryId, exp: Option<u64>) -> Arc<AttributeMap> {
        let context = Arc::new(AttributeMap::default());
        context.insert(repository);
        if let Some(exp) = exp {
            context.insert(token_claims(exp));
        }
        context
    }

    async fn run(
        service: &StorageService,
        context: &Arc<AttributeMap>,
        cmd: Cmd,
        repository: RepositoryId,
    ) -> Result<Vec<Bytes>, MessageHandleError> {
        service
            .run_request_handler(context.clone(), cmd.parsed(repository, false))
            .await
    }

    fn assert_token_expired(service: &StorageService, error: &MessageHandleError, case: &str) {
        assert!(
            matches!(error, MessageHandleError::AuthorizationFailure(message) if message == "token expired"),
            "{case}: expected the token-expired refusal, got {error:?}"
        );
        let info = service.transform_protocol_error(error);
        assert_eq!(
            info.response_error_code,
            QuicServiceError::NotAuthorized as QuicErrorStatus,
            "{case}: urc/0.2 answers NotAuthorized (2)"
        );
        assert_eq!(info.response_error_code, 2, "{case}");
    }

    #[tokio::test]
    async fn an_expired_connection_token_is_not_authorized_for_every_gated_command() {
        for cmd in MUTATIONS.into_iter().chain(READS) {
            let case = format!("{cmd:?} (reads gated = {TOKEN_EXPIRY_GATES_READS})");
            let stores = Stores::new().await;
            let repository = random::<RepositoryId>();
            // Write enforcement off: the only thing that can refuse a mutation is the expiry.
            let service = legacy(COMPATIBLE, &stores, true, false);
            let context = connection(repository, expired_exp());
            let result = run(&service, &context, cmd, repository).await;
            if refused_when_expired(cmd) {
                let error = result.expect_err(&format!("{case}: must be refused"));
                assert_token_expired(&service, &error, &case);
                assert_eq!(
                    stores.calls(),
                    0,
                    "{case}: a refused command touched a store"
                );
            } else {
                assert!(
                    !matches!(
                        result,
                        Err(MessageHandleError::AuthorizationFailure(ref message))
                            if message == "token expired"
                    ),
                    "{case}: switch off, reads stay open, got {result:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn an_unexpired_connection_token_is_unaffected() {
        let unexpired = [
            ("valid for an hour", exp_valid_for(3600)),
            (
                "past exp, inside the leeway",
                now_unix_secs().saturating_sub(TOKEN_EXP_LEEWAY_SECS / 2),
            ),
        ];
        for (name, exp) in unexpired {
            for cmd in MUTATIONS.into_iter().chain(READS) {
                let case = format!("{name} {cmd:?}");
                let stores = Stores::new().await;
                let repository = random::<RepositoryId>();
                let service = legacy(COMPATIBLE, &stores, true, false);
                let context = connection(repository, Some(exp));
                let result = run(&service, &context, cmd, repository).await;
                assert!(
                    !matches!(
                        result,
                        Err(MessageHandleError::AuthorizationFailure(ref message))
                            if message == "token expired"
                    ),
                    "{case}: got {result:?}"
                );
                if cmd.reaches_counted_store(Protocol::Legacy) {
                    assert!(stores.calls() > 0, "{case}: never reached the store");
                }
            }
        }
    }

    /// Expiry is answered ahead of caller admission and the write gate.
    #[tokio::test]
    async fn expiry_is_answered_before_admission_and_the_write_gate() {
        for cmd in MUTATIONS {
            let case = format!("{cmd:?}");
            let repository = random::<RepositoryId>();
            let stores = Stores::new().await;
            // Strict + write enforcement on + a token with no write grant: 200 or "write
            // permission required" would both be available; expiry wins.
            let service = legacy(STRICT, &stores, true, true);
            let context = connection(repository, expired_exp());
            let error = run(&service, &context, cmd, repository)
                .await
                .expect_err(&case);
            assert_token_expired(&service, &error, &case);
            assert_eq!(stores.calls(), 0, "{case}");

            // Control: unexpired, the same service shape reaches admission (200).
            let stores = Stores::new().await;
            let service = legacy(STRICT, &stores, true, true);
            let context = connection(repository, Some(exp_valid_for(3600)));
            let error = run(&service, &context, cmd, repository)
                .await
                .expect_err(&case);
            assert!(
                matches!(error, MessageHandleError::UnsupportedClient),
                "{case} control: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn connect_is_not_gated_by_expiry() {
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        let service = legacy(COMPATIBLE, &stores, true, true);
        let context = connection(repository, expired_exp());
        let connect =
            parse_message_for_opcode(Command::Authorize as u8, Bytes::from(vec![0u8; 16]))
                .expect("Connect parses");
        let result = service.run_request_handler(context, connect).await;
        assert!(
            !matches!(
                result,
                Err(MessageHandleError::AuthorizationFailure(ref message))
                    if message == "token expired"
            ),
            "Connect re-authenticates and must reach its own handler, got {result:?}"
        );
    }

    #[tokio::test]
    async fn auth_off_never_checks_the_token() {
        for cmd in MUTATIONS.into_iter().chain(READS) {
            let stores = Stores::new().await;
            let repository = random::<RepositoryId>();
            // No verifier: even a stray expired token in the context is not consulted.
            let service = legacy(COMPATIBLE, &stores, false, false);
            let context = connection(repository, expired_exp());
            let result = run(&service, &context, cmd, repository).await;
            assert!(
                !matches!(
                    result,
                    Err(MessageHandleError::AuthorizationFailure(ref message))
                        if message == "token expired"
                ),
                "{cmd:?}: got {result:?}"
            );
        }
    }

    // A real verifier, so a re-Connect really verifies the fresh token.
    const KID: &str = "wp124-reconnect-key";
    const SECRET: &[u8] = b"wp124-reconnect-hs256-secret";
    const AUDIENCE: &str = "wp124-reconnect-audience";

    #[derive(Debug)]
    struct StaticJwkService;

    #[async_trait]
    impl lore_server::auth::jwk::JWKService for StaticJwkService {
        async fn get_key(
            &self,
            kid: &str,
        ) -> Result<
            (jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm),
            lore_server::auth::jwk::JWKServiceError,
        > {
            self.get_cached_key(kid)
                .ok_or(lore_server::auth::jwk::JWKServiceError::NotFound)
        }

        fn get_cached_key(
            &self,
            kid: &str,
        ) -> Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)> {
            (kid == KID).then(|| {
                (
                    jsonwebtoken::DecodingKey::from_secret(SECRET),
                    jsonwebtoken::Algorithm::HS256,
                )
            })
        }

        async fn refresh_key(
            &self,
            _kid: &str,
        ) -> Result<
            Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)>,
            lore_server::auth::jwk::JWKServiceError,
        > {
            Ok(None)
        }
    }

    fn mint(exp: u64) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let claims = serde_json::json!({
            "sub": "reconnect-user",
            "iss": "wp124-reconnect-issuer",
            "iat": 0,
            "exp": exp,
            "aud": [AUDIENCE],
        });
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(SECRET),
        )
        .expect("minting a test token")
    }

    fn connect_request(repository: RepositoryId, token: &str) -> ParsedStorageRequest {
        let mut bytes = repository.as_bytes().to_vec();
        bytes.extend_from_slice(token.as_bytes());
        parse_message_for_opcode(Command::Authorize as u8, Bytes::from(bytes))
            .expect("Connect parses")
    }

    /// After the expired-token refusal (status 2), a re-Connect with a fresh token on the SAME
    /// connection context restores access: the new token replaces the expired one.
    #[tokio::test]
    async fn a_reconnect_with_a_fresh_token_restores_access_on_the_same_connection() {
        let stores = Stores::new().await;
        let repository = random::<RepositoryId>();
        let service = StorageService::new(
            Arc::new(Some(JwtVerifier {
                jwk_service: Arc::new(StaticJwkService),
                jwt_issuer: None,
                jwt_audience: Some(vec![AUDIENCE.to_string()]),
                jwt_typ: None,
                identity_claim: lore_server::auth::jwt::DEFAULT_IDENTITY_CLAIM.to_string(),
            })),
            Arc::new(AllowAllRepositoryAuthorizer),
            stores.immutable.clone(),
            stores.local.clone(),
            stores.mutable.clone(),
            false,
        )
        .with_caller_capability_policy(COMPATIBLE);
        // One connection: its context lives across all four steps.
        let context = connection(repository, expired_exp());

        let error = run(&service, &context, Cmd::Put, repository)
            .await
            .expect_err("the connection's token has expired");
        assert_token_expired(&service, &error, "before the reconnect");
        assert_eq!(stores.calls(), 0);

        // A Connect with a token still expired beyond the leeway is refused by the verifier, and
        // the connection stays refused.
        let stale = mint(exp_expired_for(600));
        let refused = service
            .run_request_handler(context.clone(), connect_request(repository, &stale))
            .await;
        assert!(refused.is_err(), "an expired token cannot reconnect");
        let error = run(&service, &context, Cmd::Put, repository)
            .await
            .expect_err("still expired");
        assert_token_expired(&service, &error, "after a refused reconnect");

        // A fresh token restores access.
        service
            .run_request_handler(
                context.clone(),
                connect_request(repository, &mint(exp_valid_for(3600))),
            )
            .await
            .expect("a fresh token reconnects");
        run(&service, &context, Cmd::Put, repository)
            .await
            .expect("the same connection writes again");
        assert!(stores.calls() > 0, "the put reached the store");
    }
}

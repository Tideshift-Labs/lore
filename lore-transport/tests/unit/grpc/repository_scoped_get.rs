// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! Policy tests for `scoped_repository_get`, the decision behind `Repository::query_scoped`.
//!
//! The three effects (exchange, scoped read, identity read) are injected, so every case here is
//! offline. The "sweep" tests drive repeated reads against a small model of the auth service and
//! the server that mirrors the real contract:
//!
//! - Auth service: serves a cached scoped token while unexpired, with no membership check. On a
//!   miss or expiry it grants only if the user is a member AND the repository exists, otherwise
//!   `NotAuthorized`.
//! - Server: a scoped-token `RepositoryGet` answers from the token's claim (`Ok` if the
//!   repository exists, `NotFound` if deleted), with no membership check. An identity-token
//!   `RepositoryGet` checks membership online (`NotFound` if not a member or deleted).

use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore_base::error::Disconnected;
use lore_base::error::NotAuthenticated;
use lore_base::error::NotAuthorized;
use lore_base::error::NotFound;
use lore_base::error::SlowDown;
use lore_base::types::RepositoryId;
use lore_transport::auth::exchange::ExchangeError;
use lore_transport::error::ProtocolError;
use lore_transport::grpc::scoped_repository_get;
use lore_transport::types::RepositoryData;

fn repository_id() -> RepositoryId {
    RepositoryId::from([0x7Au8; 16])
}

fn repository(name: &str) -> RepositoryData {
    RepositoryData {
        id: repository_id(),
        name: name.to_string(),
        metadata: Default::default(),
        generation: None,
    }
}

fn not_found() -> ProtocolError {
    ProtocolError::from(NotFound)
}

/// Counters and captured token for one policy invocation.
#[derive(Default)]
struct Fakes {
    scoped_calls: AtomicUsize,
    identity_calls: AtomicUsize,
    scoped_token: Mutex<Option<String>>,
}

impl Fakes {
    fn scoped(&self) -> usize {
        self.scoped_calls.load(Ordering::Relaxed)
    }

    fn identity(&self) -> usize {
        self.identity_calls.load(Ordering::Relaxed)
    }

    async fn run(
        &self,
        exchange: Result<String, ExchangeError>,
        scoped_result: Result<RepositoryData, ProtocolError>,
        identity_result: Result<RepositoryData, ProtocolError>,
    ) -> Result<RepositoryData, ProtocolError> {
        scoped_repository_get(
            || async move { exchange },
            |token| async move {
                self.scoped_calls.fetch_add(1, Ordering::Relaxed);
                *self.scoped_token.lock().expect("token mutex") = Some(token);
                scoped_result
            },
            || async move {
                self.identity_calls.fetch_add(1, Ordering::Relaxed);
                identity_result
            },
        )
        .await
    }
}

#[tokio::test]
async fn granted_reads_with_the_exact_scoped_token_and_never_the_identity() {
    let fakes = Fakes::default();

    let result = fakes
        .run(
            Ok("scoped-token-abc".to_string()),
            Ok(repository("scoped")),
            Ok(repository("identity")),
        )
        .await;

    assert_eq!(result.expect("granted read must succeed").name, "scoped");
    assert_eq!(fakes.scoped(), 1);
    assert_eq!(
        fakes.identity(),
        0,
        "a grant must not touch the identity read"
    );
    assert_eq!(
        fakes.scoped_token.lock().expect("token mutex").as_deref(),
        Some("scoped-token-abc"),
        "the scoped read must receive the exchanged token verbatim",
    );
}

#[tokio::test]
async fn denied_falls_back_to_exactly_one_identity_read_and_returns_its_not_found() {
    let fakes = Fakes::default();

    let result = fakes
        .run(
            Err(ExchangeError::from(NotAuthorized)),
            Ok(repository("scoped")),
            Err(not_found()),
        )
        .await;

    assert!(
        result.is_err_and(|err| err.is_not_found()),
        "the identity read's NotFound must reach the caller",
    );
    assert_eq!(fakes.identity(), 1, "denied must read once as the identity");
    assert_eq!(
        fakes.scoped(),
        0,
        "denied must never present a scoped token"
    );
}

#[tokio::test]
async fn denied_returns_the_identity_read_success_when_still_a_member() {
    let fakes = Fakes::default();

    let result = fakes
        .run(
            Err(ExchangeError::from(NotAuthorized)),
            Err(not_found()),
            Ok(repository("identity")),
        )
        .await;

    assert_eq!(result.expect("identity read ok").name, "identity");
    assert_eq!(fakes.identity(), 1);
    assert_eq!(fakes.scoped(), 0);
}

#[tokio::test]
async fn non_denied_exchange_failures_do_not_fall_back() {
    let failures: Vec<(&str, ExchangeError)> = vec![
        ("disconnected", ExchangeError::from(Disconnected)),
        ("internal", ExchangeError::internal("auth service exploded")),
        (
            "not authenticated",
            ExchangeError::from(NotAuthenticated::new("no identity".to_string())),
        ),
        ("slow down", ExchangeError::from(SlowDown)),
    ];

    for (label, failure) in failures {
        let fakes = Fakes::default();

        let result = fakes
            .run(
                Err(failure),
                Ok(repository("scoped")),
                Ok(repository("identity")),
            )
            .await;

        let err = result.expect_err(label);
        assert!(
            !err.is_not_found(),
            "{label}: must not be disguised as NotFound: {err:?}"
        );
        assert_eq!(fakes.scoped(), 0, "{label}: scoped read must not run");
        assert_eq!(
            fakes.identity(),
            0,
            "{label}: no fallback to the identity read"
        );
    }
}

#[tokio::test]
async fn disconnected_stays_disconnected() {
    let fakes = Fakes::default();

    let result = fakes
        .run(
            Err(ExchangeError::from(Disconnected)),
            Ok(repository("scoped")),
            Ok(repository("identity")),
        )
        .await;

    assert!(result.is_err_and(|err| err.is_disconnected()));
}

#[tokio::test]
async fn empty_token_is_an_error_and_runs_neither_read() {
    let fakes = Fakes::default();

    let result = fakes
        .run(
            Ok(String::new()),
            Ok(repository("scoped")),
            Ok(repository("identity")),
        )
        .await;

    let err = result.expect_err("an empty token must not be used");
    assert!(err.is_internal(), "{err:?}");
    assert_eq!(fakes.scoped(), 0);
    assert_eq!(fakes.identity(), 0);
}

// ---------------------------------------------------------------------------------------
// Sweep scenarios against a model of the auth service + server.
// ---------------------------------------------------------------------------------------

/// How long the model's cached scoped token lives, in ticks.
const TOKEN_TTL: u64 = 300;

#[derive(Default)]
struct WorldState {
    now: u64,
    is_member: bool,
    repo_exists: bool,
    /// Expiry tick of the cached scoped token, if one was issued.
    token_expiry: Option<u64>,
    exchanges: usize,
    scoped_reads: usize,
    identity_reads: usize,
}

struct World {
    state: Mutex<WorldState>,
}

impl World {
    fn new() -> Self {
        Self {
            state: Mutex::new(WorldState {
                is_member: true,
                repo_exists: true,
                ..Default::default()
            }),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut WorldState) -> R) -> R {
        f(&mut self.state.lock().expect("world mutex"))
    }

    fn advance(&self, ticks: u64) {
        self.with(|s| s.now += ticks);
    }

    /// The auth service's exchange.
    fn exchange(&self) -> Result<String, ExchangeError> {
        self.with(|s| {
            if s.token_expiry.is_some_and(|expiry| s.now < expiry) {
                // Served from cache: no membership check.
                return Ok("scoped-token".to_string());
            }
            if s.is_member && s.repo_exists {
                s.exchanges += 1;
                s.token_expiry = Some(s.now + TOKEN_TTL);
                Ok("scoped-token".to_string())
            } else {
                Err(ExchangeError::from(NotAuthorized))
            }
        })
    }

    /// The server's scoped-token `RepositoryGet`: answers from the claim.
    fn scoped_get(&self) -> Result<RepositoryData, ProtocolError> {
        self.with(|s| {
            s.scoped_reads += 1;
            if s.repo_exists {
                Ok(repository("repo"))
            } else {
                Err(not_found())
            }
        })
    }

    /// The server's identity-token `RepositoryGet`: checks membership online.
    fn identity_get(&self) -> Result<RepositoryData, ProtocolError> {
        self.with(|s| {
            s.identity_reads += 1;
            if s.is_member && s.repo_exists {
                Ok(repository("repo"))
            } else {
                Err(not_found())
            }
        })
    }

    async fn read(&self) -> Result<RepositoryData, ProtocolError> {
        scoped_repository_get(
            || async { self.exchange() },
            |_token| async { self.scoped_get() },
            || async { self.identity_get() },
        )
        .await
    }
}

#[tokio::test]
async fn sweep_reads_ok_with_one_exchange_while_the_token_is_valid() {
    let world = World::new();

    for _ in 0..5 {
        world.read().await.expect("read inside the token window");
        world.advance(10);
    }

    world.with(|s| {
        assert_eq!(s.exchanges, 1, "the cached token must be reused");
        assert_eq!(s.scoped_reads, 5);
        assert_eq!(s.identity_reads, 0);
    });
}

#[tokio::test]
async fn revoke_inside_token_window_is_not_observed_until_expiry() {
    let world = World::new();
    world.read().await.expect("initial read");

    world.with(|s| s.is_member = false);
    world.advance(TOKEN_TTL - 1);

    // Pinned behavior: the cached token is still valid, so the revocation is NOT seen.
    world
        .read()
        .await
        .expect("revocation is not observed while the cached token is valid");
    world.with(|s| assert_eq!(s.identity_reads, 0));
}

#[tokio::test]
async fn delete_inside_token_window_reads_not_found() {
    let world = World::new();
    world.read().await.expect("initial read");

    world.with(|s| s.repo_exists = false);
    world.advance(TOKEN_TTL - 1);

    let result = world.read().await;
    assert!(
        result.is_err_and(|err| err.is_not_found()),
        "a deleted repository is NotFound even with a valid token",
    );
    world.with(|s| assert_eq!(s.identity_reads, 0));
}

#[tokio::test]
async fn revoke_after_token_expiry_falls_back_to_identity_and_reads_not_found() {
    let world = World::new();
    world.read().await.expect("initial read");

    world.with(|s| s.is_member = false);
    world.advance(TOKEN_TTL);

    let result = world.read().await;
    assert!(
        result.is_err_and(|err| err.is_not_found()),
        "after expiry a revoked member must read NotFound",
    );
    world.with(|s| {
        assert_eq!(
            s.identity_reads, 1,
            "the identity fallback must be the path taken"
        );
        assert_eq!(
            s.scoped_reads, 1,
            "no scoped read after the grant was denied"
        );
    });
}

#[tokio::test]
async fn delete_after_token_expiry_falls_back_to_identity_and_reads_not_found() {
    let world = World::new();
    world.read().await.expect("initial read");

    world.with(|s| s.repo_exists = false);
    world.advance(TOKEN_TTL);

    let result = world.read().await;
    assert!(result.is_err_and(|err| err.is_not_found()));
    world.with(|s| {
        assert_eq!(s.identity_reads, 1, "denied exchange must fall back once");
        assert_eq!(s.scoped_reads, 1);
    });
}

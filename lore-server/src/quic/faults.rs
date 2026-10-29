// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, WP-124 follow-up (d)): fault injection for managed QUIC storage writes.
//!
//! # Why this exists
//!
//! The client-recovery acceptance cases cut a managed write's answer with an HTTP/2 proxy. That
//! proxy cannot see QUIC: the traffic is UDP, it is TLS even for `lore://` (the client only skips
//! certificate verification), and a QUIC `Put` carries no attempt id to select it by. The server
//! is the one place that knows, per command, the session, whether it was declared, the
//! repository, the verb and whether the store accepted it. So the faults are injected here.
//!
//! # The default build cannot name this
//!
//! `quic/mod.rs` declares this module only under `failure_generator`, and every call site sits in
//! a `#[cfg(feature = "failure_generator")]` block. A default build has no control listener, no
//! hook and none of these literals. A reference from unguarded code is a compile error (E0432 or
//! E0433),
//! never a silently inert call.
//!
//! # Faults
//!
//! Every arm fires **at most once**, on the first matching command, and is spent by it. A command
//! matches when its session was declared, its repository is the armed one and its verb is the
//! armed verb.
//!
//! - `answer-loss`: the store accepted the write; the answer is held until a disarm or until the
//!   connection closes. The connection stays open. The client's managed answer bound ends the
//!   write as a lost answer, which it never resends. A disarm releases the held answer late.
//! - `close-after-answer`: the store accepted the write; the connection is then closed with
//!   [`FAULT_CLOSE_CODE`] before the answer is written.
//! - `expire-session`: the command is refused as session-expired (storage status 201) before
//!   dispatch, exactly as a real expired token is. It has no store effect.
//!
//! # Control
//!
//! [`CONTROL_ENV`] names a loopback `host:port`. Unset, there is no listener. The listener refuses
//! a non-loopback address and any port a configured public or internal listener uses, so it can
//! never share the QUIC, gRPC or HTTP surface. Routes: `GET /quic-faults/state`,
//! `POST /quic-faults/arm`, `POST /quic-faults/disarm`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Result;
use anyhow::anyhow;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing;
use lore_base::types::Address;
use lore_revision::lore::RepositoryId;
use parking_lot::Mutex;
use quinn::VarInt;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::warn;

use crate::protocol::attribute_map::AttributeMap;
use crate::protocol::attribute_map::ConnectionId;
use crate::settings::Settings;

/// The loopback `host:port` of the fault-control listener. Unset means no listener.
pub const CONTROL_ENV: &str = "LORE_QUIC_FAULT_CONTROL";

/// The QUIC application close code of a `close-after-answer` fault. Not 0, so neither peer reads
/// the close as graceful.
pub const FAULT_CLOSE_CODE: u32 = 0x51_46;

/// Logged when the control listener starts.
pub const QUIC_FAULTS_COMPILED_BANNER: &str = "WARNING: QUIC storage faults are compiled in \
     (failure_generator). LORE_QUIC_FAULT_CONTROL can withhold a managed write's answer, close its \
     connection or expire its session. This is a TEST binary and must not serve production traffic.";

/// How many firings [`Registry::state`] keeps, oldest dropped first.
const MAX_FIRINGS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fault {
    AnswerLoss,
    CloseAfterAnswer,
    ExpireSession,
}

/// The managed storage writes a fault can select.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriteVerb {
    Put,
    Copy,
    PutResolved,
}

/// Body of `POST /quic-faults/arm`. `verb` defaults to `put`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmRequest {
    pub fault: Fault,
    /// 32 lowercase hex characters.
    pub repository: String,
    #[serde(default)]
    pub verb: Option<WriteVerb>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Armed {
    pub id: u64,
    pub fault: Fault,
    pub verb: WriteVerb,
    pub repository: String,
}

/// One fault that fired, as evidence.
#[derive(Clone, Debug, Serialize)]
pub struct Firing {
    pub arm_id: u64,
    pub fault: Fault,
    pub verb: WriteVerb,
    pub repository: String,
    pub connection_id: Option<usize>,
    pub session_id: u32,
    /// The written address, `hash-context` hex. `None` for an expired command, which was never
    /// dispatched.
    pub address: Option<String>,
    /// Whether the store accepted the write before the fault fired.
    pub store_accepted: bool,
    /// For `close-after-answer`: whether a connection handle was present and was closed.
    pub connection_closed: bool,
    /// For `answer-loss`: how the hold ended. `None` while it is held, and for every other fault.
    pub hold_end: Option<HoldEnd>,
    pub at_unix_ms: u128,
}

/// How a held `answer-loss` answer was let go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HoldEnd {
    /// A disarm released it; the answer was then written, late.
    Disarm,
    /// Its connection closed first; there was no one to answer.
    ConnectionClosed,
    /// The command's task was dropped while holding (stream reset, server shutdown).
    Cancelled,
}

/// Counts one held answer and records how its hold ended, on every exit, cancellation included.
struct HoldGuard<'registry> {
    registry: &'registry Registry,
    arm_id: u64,
    end: HoldEnd,
}

impl<'registry> HoldGuard<'registry> {
    fn new(registry: &'registry Registry, arm_id: u64) -> Self {
        registry.inner.lock().held += 1;
        Self {
            registry,
            arm_id,
            end: HoldEnd::Cancelled,
        }
    }
}

impl Drop for HoldGuard<'_> {
    fn drop(&mut self) {
        let mut inner = self.registry.inner.lock();
        inner.held = inner.held.saturating_sub(1);
        if let Some(firing) = inner
            .fired
            .iter_mut()
            .find(|firing| firing.arm_id == self.arm_id)
        {
            firing.hold_end = Some(self.end);
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FaultState {
    pub compiled: bool,
    pub armed: Option<Armed>,
    /// Answers held right now.
    pub held: usize,
    pub fired: Vec<Firing>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ArmError {
    AlreadyArmed,
    InvalidRepository,
}

/// The QUIC connection a command arrived on, stored in its connection context so a
/// `close-after-answer` fault can close it.
pub struct FaultConnection(pub quinn::Connection);

struct Inner {
    next_id: u64,
    armed: Option<(Armed, RepositoryId)>,
    held: usize,
    fired: Vec<Firing>,
}

/// The armed fault and its evidence. One process-wide instance serves the hooks
/// ([`registry`]); tests build their own.
pub struct Registry {
    inner: Mutex<Inner>,
    /// Bumped by every disarm; a held answer waits for it to move.
    release: watch::Sender<u64>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                next_id: 1,
                armed: None,
                held: 0,
                fired: Vec::new(),
            }),
            release: watch::Sender::new(0),
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or_default()
}

/// The process-wide registry the storage hooks and the control listener share.
pub fn registry() -> &'static Arc<Registry> {
    static REGISTRY: LazyLock<Arc<Registry>> = LazyLock::new(|| Arc::new(Registry::default()));
    &REGISTRY
}

impl Registry {
    pub fn arm(&self, request: ArmRequest) -> Result<Armed, ArmError> {
        let repository_hex = request.repository;
        if repository_hex.len() != 32
            || !repository_hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ArmError::InvalidRepository);
        }
        let repository: RepositoryId = repository_hex
            .parse()
            .map_err(|_invalid| ArmError::InvalidRepository)?;
        let mut inner = self.inner.lock();
        if inner.armed.is_some() {
            return Err(ArmError::AlreadyArmed);
        }
        let armed = Armed {
            id: inner.next_id,
            fault: request.fault,
            verb: request.verb.unwrap_or(WriteVerb::Put),
            repository: repository_hex,
        };
        inner.next_id += 1;
        inner.armed = Some((armed.clone(), repository));
        Ok(armed)
    }

    /// Clear an unfired arm and release every held answer. Firings stay as evidence; a released
    /// hold records [`HoldEnd::Disarm`] itself.
    pub fn disarm(&self) {
        self.inner.lock().armed = None;
        self.release.send_modify(|generation| *generation += 1);
    }

    pub fn state(&self) -> FaultState {
        let inner = self.inner.lock();
        FaultState {
            compiled: true,
            armed: inner.armed.as_ref().map(|(armed, _)| armed.clone()),
            held: inner.held,
            fired: inner.fired.clone(),
        }
    }

    /// Spend the arm if `fault` is armed for this command. One lock, so two concurrent commands
    /// can never both claim it.
    fn claim(
        &self,
        fault: Fault,
        repository: RepositoryId,
        declared: bool,
        verb: WriteVerb,
    ) -> Option<Armed> {
        let mut inner = self.inner.lock();
        let matches = inner
            .armed
            .as_ref()
            .is_some_and(|(armed, armed_repository)| {
                declared
                    && armed.fault == fault
                    && armed.verb == verb
                    && *armed_repository == repository
            });
        if !matches {
            return None;
        }
        inner.armed.take().map(|(armed, _)| armed)
    }

    fn record(&self, firing: Firing) {
        let mut inner = self.inner.lock();
        if inner.fired.len() == MAX_FIRINGS {
            inner.fired.remove(0);
        }
        inner.fired.push(firing);
    }

    /// Before dispatch: whether to refuse this command as session-expired.
    pub fn force_expired(
        &self,
        connection_id: Option<usize>,
        session_id: u32,
        repository: RepositoryId,
        declared: bool,
        verb: Option<WriteVerb>,
    ) -> bool {
        let Some(verb) = verb else {
            return false;
        };
        let Some(armed) = self.claim(Fault::ExpireSession, repository, declared, verb) else {
            return false;
        };
        self.record(Firing {
            arm_id: armed.id,
            fault: armed.fault,
            verb,
            repository: armed.repository,
            connection_id,
            session_id,
            address: None,
            store_accepted: false,
            connection_closed: false,
            hold_end: None,
            at_unix_ms: now_ms(),
        });
        true
    }

    /// After the store accepted a write: apply an armed answer fault. Returns once the answer may
    /// be written (it may then find its connection gone).
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per fact the storage hook already holds; a struct would exist only for this call"
    )]
    pub async fn after_write(
        &self,
        connection_id: Option<usize>,
        connection: Option<&quinn::Connection>,
        session_id: u32,
        repository: RepositoryId,
        declared: bool,
        verb: WriteVerb,
        address: Option<&Address>,
    ) {
        // Subscribed before the claim: a disarm landing between the claim and the wait below
        // still moves the value this receiver has not seen, so the hold cannot miss it.
        let mut release = self.release.subscribe();
        let claimed = self
            .claim(Fault::AnswerLoss, repository, declared, verb)
            .or_else(|| self.claim(Fault::CloseAfterAnswer, repository, declared, verb));
        let Some(armed) = claimed else {
            return;
        };
        let close = armed.fault == Fault::CloseAfterAnswer;
        if close && let Some(connection) = connection {
            connection.close(
                VarInt::from_u32(FAULT_CLOSE_CODE),
                b"quic fault: close-after-answer",
            );
        }
        self.record(Firing {
            arm_id: armed.id,
            fault: armed.fault,
            verb,
            repository: armed.repository,
            connection_id,
            session_id,
            address: address.map(ToString::to_string),
            store_accepted: true,
            connection_closed: close && connection.is_some(),
            hold_end: None,
            at_unix_ms: now_ms(),
        });
        if close {
            if connection.is_none() {
                warn!("close-after-answer fired with no connection handle; the answer is sent");
            }
            return;
        }
        let mut hold = HoldGuard::new(self, armed.id);
        hold.end = if let Some(connection) = connection {
            tokio::select! {
                _released = release.changed() => HoldEnd::Disarm,
                _closed = connection.closed() => HoldEnd::ConnectionClosed,
            }
        } else {
            let _released = release.changed().await;
            HoldEnd::Disarm
        };
    }
}

/// The connection id and handle the hooks read from a command's connection context.
pub fn connection_of(context: &AttributeMap) -> (Option<usize>, Option<Arc<FaultConnection>>) {
    (
        context.get::<ConnectionId>().map(|id| id.0),
        context.get::<FaultConnection>(),
    )
}

/// Every port a configured public or internal listener binds.
pub fn reserved_ports(settings: &Settings) -> Vec<i32> {
    let server = &settings.server;
    [
        server.grpc.as_ref().map(|grpc| grpc.port),
        server.grpc_internal.as_ref().map(|grpc| grpc.port),
        server.http.as_ref().map(|http| http.port),
        server.quic.as_ref().map(|quic| quic.port),
        server.quic_internal.as_ref().map(|quic| quic.port),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Parse [`CONTROL_ENV`]'s value: a loopback address on a port no listener uses.
pub fn validate_control_address(raw: &str, reserved: &[i32]) -> Result<SocketAddr> {
    let address: SocketAddr = raw
        .parse()
        .map_err(|err| anyhow!("{CONTROL_ENV}={raw:?} is not a socket address: {err}"))?;
    if !address.ip().is_loopback() {
        return Err(anyhow!(
            "{CONTROL_ENV} must be a loopback address, got {address}"
        ));
    }
    if address.port() == 0 || reserved.contains(&i32::from(address.port())) {
        return Err(anyhow!(
            "{CONTROL_ENV} port {} is 0 or used by a configured listener",
            address.port()
        ));
    }
    Ok(address)
}

/// The control address from the environment, or `None` when [`CONTROL_ENV`] is unset.
pub fn control_address_from_env(settings: &Settings) -> Result<Option<SocketAddr>> {
    match std::env::var(CONTROL_ENV) {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(anyhow!("{CONTROL_ENV}: {err}")),
        Ok(raw) => validate_control_address(&raw, &reserved_ports(settings)).map(Some),
    }
}

async fn get_state(State(registry): State<Arc<Registry>>) -> Json<FaultState> {
    Json(registry.state())
}

async fn post_arm(
    State(registry): State<Arc<Registry>>,
    Json(request): Json<ArmRequest>,
) -> Result<Json<FaultState>, (StatusCode, &'static str)> {
    match registry.arm(request) {
        Ok(_armed) => Ok(Json(registry.state())),
        Err(ArmError::AlreadyArmed) => Err((StatusCode::CONFLICT, "already-armed")),
        Err(ArmError::InvalidRepository) => Err((StatusCode::BAD_REQUEST, "invalid-repository")),
    }
}

async fn post_disarm(State(registry): State<Arc<Registry>>) -> Json<FaultState> {
    registry.disarm();
    Json(registry.state())
}

pub fn control_router(registry: Arc<Registry>) -> Router {
    Router::new()
        .route("/quic-faults/state", routing::get(get_state))
        .route("/quic-faults/arm", routing::post(post_arm))
        .route("/quic-faults/disarm", routing::post(post_disarm))
        .with_state(registry)
}

/// Serve the control routes on `address` until shutdown.
pub async fn serve_control(address: SocketAddr, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let listener = TcpListener::bind(address).await.map_err(|err| {
        anyhow!("Failed to bind the QUIC fault-control listener {address}: {err}")
    })?;
    warn!(%address, "{QUIC_FAULTS_COMPILED_BANNER} Fault control is listening.");
    axum::serve(listener, control_router(registry().clone()))
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|&stop| stop).await;
        })
        .await
        .map_err(|err| anyhow!("QUIC fault-control listener failed: {err}"))
}

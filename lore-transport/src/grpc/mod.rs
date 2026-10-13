// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
mod admin_client;
#[cfg(not(feature = "test-util"))]
mod domain_operation_client;
#[cfg(feature = "test-util")]
pub mod domain_operation_client;
#[cfg(not(feature = "test-util"))]
mod environment_client;
#[cfg(feature = "test-util")]
pub mod environment_client;
#[cfg(not(feature = "test-util"))]
mod lock_client;
#[cfg(feature = "test-util")]
pub mod lock_client;
mod repository_client;
#[cfg(not(feature = "test-util"))]
mod revision_client;
#[cfg(feature = "test-util")]
pub mod revision_client;
#[cfg(not(feature = "test-util"))]
mod storage_client;
#[cfg(feature = "test-util")]
pub mod storage_client;

use std::collections::HashMap;
use std::error::Error;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use http::header::AUTHORIZATION;
use lore_base::error::AddressNotFound;
use lore_base::lore_debug;
use lore_base::lore_info;
use lore_base::lore_trace;
use lore_base::types::*;
use lore_error_set::prelude::*;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::InterceptedService;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::ClientTlsConfig;
use tower::Layer;
use tower::Service;
use tower::ServiceBuilder;
use url::Url;

use crate::attempt_store::AcquiredLock;
use crate::attempt_store::FencedLockResource;
use crate::auth::exchange::auth_exchange;
use crate::auth::exchange::auth_exchange_custom_resource;
use crate::connection::Connection;
use crate::connection::RECONNECT_MAX_ATTEMPTS;
use crate::connection::RECONNECT_MAX_DELAY;
use crate::connection::RECONNECT_START_DELAY;
use crate::connection::SuppliedCredentials;
use crate::domain_receipt::DomainAttemptReceipt;
use crate::domain_receipt::DomainReceipt;
use crate::domain_receipt::DomainReceiptQuery;
use crate::error::ProtocolError;
use crate::outcome::AttemptId;
use crate::outcome::GrpcRpc;
use crate::outcome::grpc_replay_class;
use crate::outcome::outcome_unknown;
use crate::replay::ReplayClass;
use crate::traits::*;
use crate::types::*;

// gRPC request metadata key for repo/partition IDs. Note: these keys are required to have
// "-bin" at the end since they store binary data. It's a gRPC thing.
pub const PARTITION_ID_KEY: &str = "lore-partition-bin";
pub const REPOSITORY_ID_KEY: &str = "urc-repository-id-bin";

// TODO(mjansson): This needs to be configurable, URC source should not be Epic specific
pub const CORRELATION_ID_HEADER: &str = "x-epic-correlation-id";
pub const REVISION_LIST_STRATEGY_HEADER: &str = "x-lore-revision-list-strategy";

// PIN(WP-120, 2026-09-05): the human's own authentication JWT, sent beside
// `authorization` on a governed mutation. Plain ASCII, so no `-bin` suffix, and
// the value carries the same `Bearer <jwt>` framing `authorization` does so a
// server can forward it verbatim. Documented beside `lore-attempt-id`; the
// server half is `lore-server`'s `domain_operation_metadata::AUTHN_BEARER_KEY`
// and the two literals must stay equal.
//
// Why a second header rather than reusing `authorization`: on every service
// under [`AuthzInterceptor`], `authorization` carries the *exchanged*
// multiresource authorization token — audience `["lore-storage", <host>]` and a
// `resources` claim. A governed mutation's internal prepare forwards a bearer to
// the platform's repository-operation verifier, which authenticates the *human*
// and refuses a token carrying a `resources` claim outright. The two credentials
// have different audiences and different jobs, so they need different carriage;
// overwriting `authorization` would break the repo-scoped authz check that
// header exists for.
//
// It is a credential, never an identity assertion by this client: the server
// relays it to the verifier, which re-verifies it independently.
pub const AUTHN_BEARER_METADATA_KEY: &str = "lore-authn-bearer";

const RETRY_START_BACKOFF_MS: u64 = 50;
const RETRY_MAX_BACKOFF_MS: u64 = 10_000;
const RETRY_MAX_ATTEMPTS: usize = 60;
const GRPC_CONNECT_TIMEOUT_SECS: u64 = 5;

/// The total wall-clock time one refused RPC may spend waiting between
/// attempts. **This is the primary bound on the per-RPC retry budget**;
/// [`RETRY_MAX_ATTEMPTS`] is now a secondary one that the schedule reaches only
/// if the waits are short enough to fit sixty of them inside this.
///
/// Two minutes, chosen against what the retries are for rather than against the
/// schedule that produced them. The retryable refusal on this wire is CR-032's
/// admission gate, whose verdict a five-second readiness tick refreshes; two
/// minutes is more than twenty refreshes, so a cell that recovers at all
/// recovers well inside it, and a cell that has not recovered by then is not
/// one more round trip away from doing so. Past that point the retries stop
/// being patience and start being an unresponsive client.
///
/// The number this replaces was not chosen at all — it was whatever
/// `RETRY_START_BACKOFF_MS`, `RETRY_MAX_BACKOFF_MS` and `RETRY_MAX_ATTEMPTS`
/// happened to multiply out to, and it came to over ten minutes per refused
/// RPC. See [`grpc_retry`] for the measurement.
const RETRY_WALL_CLOCK_BUDGET: Duration = Duration::from_secs(120);

/// [`RETRY_MAX_BACKOFF_MS`] as a `Duration`, which is also the ceiling a
/// server-supplied retry hint is clamped to. See [`retry_delay_hint`].
const RETRY_MAX_BACKOFF: Duration = Duration::from_millis(RETRY_MAX_BACKOFF_MS);

/// The client's `RESOURCE_EXHAUSTED` retry policy for one RPC: 50 ms doubling
/// to a 10 s ceiling with up to 100 ms of jitter per wait
/// ([`crate::util::Retry`]), under a [`RETRY_WALL_CLOCK_BUDGET`] ceiling on the
/// total, and at most [`RETRY_MAX_ATTEMPTS`] attempts.
///
/// # The per-RPC budget, measured rather than assumed
///
/// The number is written down here because a server-side constant once
/// justified itself against a client that did not exist. `lore-server`'s
/// `measure_the_real_lore_client_resource_exhausted_retry_budget`
/// (`lore-server/tests/outbox_load_proof.rs`) drives the *unbudgeted* schedule
/// under a paused clock and pins constants above against this file;
/// `tests/grpc_retry_hint.rs` drives *this function's own* budgeted policy the
/// same way.
///
/// | | attempts | elapsed per refused RPC |
/// | --- | --- | --- |
/// | no server hint | 18 | 112.8 s to 114.3 s |
/// | honouring a 10 s `RetryInfo` | 11 | 110.0 s to 110.3 s |
///
/// The unhinted row: base steps 50+100+200+400+800+1600+3200+6400 ms cover the
/// first eight attempts (12.75 s), then each further attempt costs the 10,000 ms
/// ceiling, so attempt 18 ends at 112.75 s and a nineteenth would need to run
/// past 120 s. The hinted row: attempts 1 to 8 have a base step below 10 s, so
/// the hint dominates at exactly 10,000 ms each (80.0 s); attempts 9 to 11 sit
/// at the 10,000 ms ceiling plus jitter; a twelfth would pass 120 s.
///
/// **The wall-clock budget, not the attempt count, is what ends both.** Sixty
/// attempts are still allowed and no longer reachable at this backoff — they
/// bound a schedule whose steps are short, which this one's are not. Removing
/// the attempt cap would leave the budget doing all the work; it is kept as the
/// secondary bound because it costs nothing and it is the one that holds if the
/// backoff constants are ever made much smaller.
///
/// **The hint is honoured within the budget, never past it.** Each wait is
/// `max(this client's own step, the server's hint)`, and a wait that would end
/// after the deadline is not started at all — the RPC ends on the last error it
/// actually received. Truncating such a wait instead would send the next attempt
/// *earlier* than the server asked, which is the one direction that makes things
/// worse for a cell already refusing.
///
/// What honouring the hint still buys, inside the shorter budget: unhinted, the
/// first eight attempts all fall inside 12.75 s, and CR-032's admission gate
/// serves a verdict its readiness tick refreshes every five seconds — so those
/// eight were guaranteed to re-read the identical cached refusal. Every hinted
/// retry arrives after at least one whole refresh.
///
/// **It is wall clock, so the round trips spend it too.** The deadline is taken
/// when the budget is built, and everything after that draws on it: the waits,
/// the refused round trips between them, and any time spent in a stream body.
/// Slow round trips therefore buy *fewer* attempts rather than a longer RPC, so
/// the table above is the attempt count when the round trips are free, which is
/// its maximum — 5 s round trips turn the unhinted 18 into 12, and an RPC that
/// spends the whole budget in-body gets no retries at all. This is the opposite
/// of what the same paragraph said before the budget existed, when the schedule
/// counted only its own waits and every number here was a floor.
///
/// **It bounds one RPC, not one operation.** `grpc_retry()` is built per RPC, so
/// an operation issuing several refused RPCs pays the budget several times over,
/// and a verb wrapped in [`with_reconnect_classified`] builds a fresh one on
/// each of its [`crate::replay::ATTEMPT_BUDGET`] dispatches — 240 s of retry
/// waiting end to end at today's value of 2. Nothing else truncates any of it:
/// the endpoint carries no request timeout, and [`GRPC_CONNECT_TIMEOUT_SECS`]
/// bounds channel setup only.
///
/// `pub` and `#[doc(hidden)]` for the same reason as [`retry_delay_hint`]: the
/// budget suite measures the shipped policy itself rather than a copy of its
/// constants.
#[doc(hidden)]
pub fn grpc_retry() -> RetryBudget {
    RetryBudget {
        retry: crate::util::retry(
            RETRY_START_BACKOFF_MS,
            RETRY_MAX_BACKOFF_MS,
            RETRY_MAX_ATTEMPTS,
        ),
        deadline: tokio::time::Instant::now() + RETRY_WALL_CLOCK_BUDGET,
    }
}

/// One RPC's retry budget: the attempt schedule, plus the wall-clock deadline
/// that is the primary bound on it.
///
/// The deadline is taken when the budget is built, which every RPC does before
/// its first send, so it covers the whole of that RPC's retry life. It is not
/// shared: a caller issuing several RPCs builds one of these per RPC and pays
/// the budget per RPC. See [`grpc_retry`].
#[doc(hidden)]
pub struct RetryBudget {
    retry: crate::util::Retry,
    deadline: tokio::time::Instant,
}

impl RetryBudget {
    /// Attempts spent so far. Exposed for the budget suite's measurements.
    #[doc(hidden)]
    pub fn counter(&self) -> usize {
        self.retry.counter()
    }

    /// Wait out one attempt, honouring `hint`, and report whether the caller
    /// may try again. `false` ends the retry loop.
    ///
    /// The gate runs **before** the wait and refuses on the upper bound, so no
    /// wait is ever started that could end past the deadline:
    /// [`crate::util::Retry::next_delay_upper_bound`] is the most the client's
    /// own step can cost, the hint may raise it, and the sum is compared
    /// against the deadline while nothing has been slept and no attempt spent.
    /// Refusing rather than shortening is the point — a truncated wait would
    /// retry sooner than the server asked.
    ///
    /// Both refusals, this one and an exhausted attempt count, return `false`
    /// the same way, so [`handle_error`] returns the same refusal to the caller
    /// either way. Neither is a new error kind, and neither reclassifies the
    /// RPC: this seam still never authorises a redispatch.
    #[doc(hidden)]
    pub async fn wait(&mut self, hint: Option<Duration>) -> bool {
        let Some(step) = self.retry.next_delay_upper_bound() else {
            // The secondary bound: the attempt count is spent.
            return false;
        };

        let longest = match hint {
            Some(hint) => step.max(hint),
            None => step,
        };
        // `checked_add` rather than `+`: a hint arrives from the wire, and
        // `Instant + Duration` panics on overflow. A hint so large it cannot be
        // added to now is, unambiguously, one that does not fit the budget.
        let Some(ends_at) = tokio::time::Instant::now().checked_add(longest) else {
            return false;
        };
        if ends_at > self.deadline {
            return false;
        }

        wait_with_hint(&mut self.retry, hint).await
    }
}

#[derive(Default)]
pub struct GRPCAuth {
    pub remote_domain: String,
    pub authentication_token: String,
    pub authorization_token: String,
    pub refresher: Option<JoinHandle<()>>,
}

/// Hand-written, and never `#[derive]`d: both token fields are live bearer
/// credentials, and a derived `Debug` would print them in full anywhere a holder
/// of this type is formatted — which is now every governed-mutation client,
/// since each keeps its own handle. The fields are named so a reader can still
/// tell which credentials are populated.
impl std::fmt::Debug for GRPCAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn presence(token: &str) -> &'static str {
            if token.is_empty() {
                "<absent>"
            } else {
                "<redacted>"
            }
        }

        f.debug_struct("GRPCAuth")
            .field("remote_domain", &self.remote_domain)
            .field(
                "authentication_token",
                &presence(&self.authentication_token),
            )
            .field("authorization_token", &presence(&self.authorization_token))
            .field("refresher", &self.refresher.is_some())
            .finish()
    }
}

impl GRPCAuth {
    async fn new(
        auth_url: &str,
        remote_domain: &str,
        identity: &str,
        repository: RepositoryId,
        credentials: &Arc<SuppliedCredentials>,
    ) -> Arc<parking_lot::RwLock<Self>> {
        let remote_domain = remote_domain.to_string();
        // Read the credentials and take the rotation signal in one step: a
        // rotation landing during the exchange below has to stay pending, or the
        // tokens derived here would stand until the next scheduled refresh.
        let ((identity_token, access_token), rotated) = credentials.tokens_and_signal();

        let (authentication_token, authorization_token, resolved_identity) = auth_exchange(
            auth_url,
            &remote_domain,
            identity,
            repository,
            &identity_token,
            &access_token,
        )
        .await;

        let auth = Arc::new(parking_lot::RwLock::new(GRPCAuth {
            remote_domain: remote_domain.clone(),
            authentication_token,
            authorization_token,
            refresher: None,
        }));

        let auth_ref = Arc::downgrade(&auth);
        let refresher = Some(lore_base::lore_spawn_net!(grpc_auth_refresher(
            auth_ref,
            auth_url.to_string(),
            remote_domain,
            resolved_identity,
            repository,
            credentials.clone(),
            rotated,
        )));

        {
            let mut auth = auth.write();
            auth.refresher = refresher;
        }

        auth
    }

    /// Builds a `GRPCAuth` whose authorization token is scoped to an arbitrary
    /// caller-supplied resource identifier. Used for endpoints whose authz
    /// model is not repository-based.
    async fn new_for_custom_resource(
        auth_url: &str,
        remote_domain: &str,
        identity: &str,
        resource_id: &str,
        credentials: &Arc<SuppliedCredentials>,
    ) -> Arc<parking_lot::RwLock<Self>> {
        let remote_domain = remote_domain.to_string();
        // Read the credentials and take the rotation signal in one step: a
        // rotation landing during the exchange below has to stay pending, or the
        // tokens derived here would stand until the next scheduled refresh.
        let ((identity_token, access_token), rotated) = credentials.tokens_and_signal();

        let (authentication_token, authorization_token, resolved_identity) =
            auth_exchange_custom_resource(
                auth_url,
                &remote_domain,
                identity,
                resource_id,
                &identity_token,
                &access_token,
            )
            .await;

        let auth = Arc::new(parking_lot::RwLock::new(GRPCAuth {
            remote_domain: remote_domain.clone(),
            authentication_token,
            authorization_token,
            refresher: None,
        }));

        let auth_ref = Arc::downgrade(&auth);
        let refresher = Some(lore_base::lore_spawn_net!(
            grpc_auth_refresher_custom_resource(
                auth_ref,
                auth_url.to_string(),
                remote_domain,
                resolved_identity,
                resource_id.to_string(),
                credentials.clone(),
                rotated,
            )
        ));

        {
            let mut auth = auth.write();
            auth.refresher = refresher;
        }

        auth
    }
}

pub type GRPCAuthRef = Arc<parking_lot::RwLock<GRPCAuth>>;

/// How long a refresher waits before re-deriving its tokens, absent a rotation.
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Waits for the next refresh: the interval, or a rotation if one lands first.
///
/// The tokens a service client presents live in its `GRPCAuth`, which only a
/// refresher writes, and the interceptor reads them at request time. Waiting out
/// the interval after a caller supplies a replacement would leave every request
/// in between carrying the credential that was just replaced -- so a rotation
/// cuts the wait short and the tokens are re-derived at once.
async fn await_refresh(rotated: &mut tokio::sync::watch::Receiver<u64>) {
    tokio::select! {
        () = tokio::time::sleep(REFRESH_INTERVAL) => {}
        result = rotated.changed() => {
            if result.is_err() {
                // Unreachable: the refresher owns an `Arc` of the credentials the
                // sender lives in, so it cannot be dropped first. Waiting out the
                // interval anyway, because returning here would turn a closed
                // channel into a busy loop if that ever stopped holding.
                tokio::time::sleep(REFRESH_INTERVAL).await;
            } else {
                lore_debug!("Credentials replaced, refreshing the authorization now");
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn grpc_auth_refresher(
    auth: Weak<parking_lot::RwLock<GRPCAuth>>,
    auth_url: String,
    remote_domain: String,
    identity: String,
    repository: RepositoryId,
    credentials: Arc<SuppliedCredentials>,
    mut rotated: tokio::sync::watch::Receiver<u64>,
) {
    loop {
        await_refresh(&mut rotated).await;

        // Check if connection is still used
        let Some(auth) = auth.upgrade() else {
            return;
        };

        let (identity_token, access_token) = credentials.tokens();
        let (authentication_token, authorization_token, _) = auth_exchange(
            &auth_url,
            &remote_domain,
            &identity,
            repository,
            &identity_token,
            &access_token,
        )
        .await;

        apply_refreshed_tokens(&auth, authentication_token, authorization_token);
    }
}

/// Folds a refresh exchange's result into the cached auth. An empty result must
/// not clobber a still-valid token: `inject_authorization` sends NO
/// `authorization` header at all for an empty token, so a transient
/// auth-endpoint outage would otherwise wedge every subsequent request until
/// process exit even after the endpoint recovers. Keeping the previous token is
/// safe — if it has really expired the server rejects it as a bad token, which
/// is classifiable, unlike a missing header.
#[lore_macro::test_pub]
fn apply_refreshed_tokens(
    auth: &parking_lot::RwLock<GRPCAuth>,
    authentication_token: String,
    authorization_token: String,
) {
    let mut auth = auth.write();
    if !authentication_token.is_empty() {
        auth.authentication_token = authentication_token;
    }
    if !authorization_token.is_empty() {
        auth.authorization_token = authorization_token;
    }
}

#[allow(clippy::too_many_arguments)]
async fn grpc_auth_refresher_custom_resource(
    auth: Weak<parking_lot::RwLock<GRPCAuth>>,
    auth_url: String,
    remote_domain: String,
    identity: String,
    resource_id: String,
    credentials: Arc<SuppliedCredentials>,
    mut rotated: tokio::sync::watch::Receiver<u64>,
) {
    loop {
        await_refresh(&mut rotated).await;

        let Some(auth) = auth.upgrade() else {
            return;
        };

        let (identity_token, access_token) = credentials.tokens();
        let (authentication_token, authorization_token, _) = auth_exchange_custom_resource(
            &auth_url,
            &remote_domain,
            &identity,
            &resource_id,
            &identity_token,
            &access_token,
        )
        .await;

        apply_refreshed_tokens(&auth, authentication_token, authorization_token);
    }
}

pub fn inject_correlation_id(request: &mut tonic::Request<()>) -> Result<(), tonic::Status> {
    // In lore-transport, correlation_id is no longer available from ExecutionContext.
    // The correlation ID injection is now a no-op at this layer.
    // The caller (lore-core) can inject it if needed via a custom interceptor.
    let _ = request;
    Ok(())
}

pub fn inject_authorization(
    request: &mut tonic::Request<()>,
    token: &str,
) -> Result<(), tonic::Status> {
    if token.is_empty() {
        return Ok(());
    }
    let mut value = MetadataValue::from_str(&format!("Bearer {token}"))
        .map_err(|err| tonic::Status::failed_precondition(err.to_string()))?;
    value.set_sensitive(true);
    request.metadata_mut().insert(AUTHORIZATION.as_str(), value);
    Ok(())
}

/// Stamp the human's own authentication bearer onto one governed mutation.
///
/// Called per dispatch rather than from an interceptor, because a tonic
/// interceptor is handed a `Request<()>` with no method on it and every
/// [`AuthzInterceptor`] client mixes governed mutations with ordinary reads on
/// one channel. Stamping it at the call site is what keeps the credential off
/// the reads.
///
/// A silent no-op when the credential store holds no authentication token. That
/// is the service-delegation and raw-supplied-token case: those callers never
/// had a human JWT to send, and failing the dispatch here would turn a working
/// call into a certain failure over carriage the server treats as additive. An
/// enforcing cell refuses the mutation on its own terms instead, which is where
/// the refusal can name what is missing.
pub fn inject_authn_bearer<T>(
    request: &mut tonic::Request<T>,
    auth: &GRPCAuthRef,
) -> Result<(), tonic::Status> {
    // Cloned out under the lock rather than formatted under it: the read guard
    // is a `parking_lot` lock shared with the refresher task.
    let token = auth.read().authentication_token.clone();
    if token.is_empty() {
        return Ok(());
    }
    let mut value = MetadataValue::from_str(&format!("Bearer {token}"))
        .map_err(|err| tonic::Status::failed_precondition(err.to_string()))?;
    value.set_sensitive(true);
    request
        .metadata_mut()
        .insert(AUTHN_BEARER_METADATA_KEY, value);
    Ok(())
}

pub fn inject_repository(
    request: &mut tonic::Request<()>,
    repository: RepositoryId,
) -> Result<(), tonic::Status> {
    if repository.is_zero() {
        return Ok(());
    }
    let value = MetadataValue::from_bytes(repository.data());
    request
        .metadata_mut()
        .append_bin(PARTITION_ID_KEY, value.clone());
    request.metadata_mut().append_bin(REPOSITORY_ID_KEY, value);

    Ok(())
}

/// Stamp the current dispatch's attempt id onto the request, when there is one.
///
/// Silent no-op for a read, which has no attempt id. A malformed value is dropped rather than
/// failing the call: the header is additive carriage that an older server ignores, and refusing
/// to dispatch a mutation because a header would not encode would trade a working call for a
/// certain failure.
pub fn inject_attempt_id(request: &mut tonic::Request<()>) -> Result<(), tonic::Status> {
    let Some(attempt) = crate::outcome::current_dispatch_attempt() else {
        return Ok(());
    };
    // Counted before the header is built, so even a copy whose header would not encode counts.
    // Over-counting only keeps an attempt unknown; under-counting could settle one wrongly.
    crate::outcome::note_dispatch_send(attempt);
    match MetadataValue::from_str(&attempt.to_string()) {
        Ok(value) => {
            request
                .metadata_mut()
                .insert(crate::outcome::ATTEMPT_ID_METADATA_KEY, value);
        }
        Err(err) => lore_debug!("Dropping unrepresentable attempt id header: {err}"),
    }
    Ok(())
}

#[derive(Clone)]
pub struct CorrelationInterceptor;

pub(crate) fn authorization_snapshot(auth: &GRPCAuthRef) -> String {
    auth.read().authorization_token.clone()
}

impl Interceptor for CorrelationInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        inject_correlation_id(&mut request)?;
        Ok(request)
    }
}

#[derive(Clone)]
pub struct AuthnInterceptor {
    pub auth: Arc<parking_lot::RwLock<GRPCAuth>>,
}

impl Interceptor for AuthnInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        inject_correlation_id(&mut request)?;
        inject_authorization(&mut request, self.auth.read().authentication_token.as_str())?;
        inject_attempt_id(&mut request)?;
        Ok(request)
    }
}

#[derive(Clone)]
pub struct AuthzInterceptor {
    pub repository: RepositoryId,
    pub auth: Arc<parking_lot::RwLock<GRPCAuth>>,
}

impl Interceptor for AuthzInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        inject_correlation_id(&mut request)?;
        let authorization = crate::caller_operation::current_dispatch_authorization()
            .unwrap_or_else(|| self.auth.read().authorization_token.clone());
        if let Some(recovery) = crate::caller_operation::current_caller_recovery() {
            let token = lore_credential::insecure_decode_token(&authorization).map_err(|_err| {
                tonic::Status::failed_precondition("recovery credential namespace is unavailable")
            })?;
            if recovery.repository != self.repository
                || recovery.verified_issuer != token.claims.issuer
                || recovery.authenticated_subject != token.claims.user_id
                || recovery.caller_capabilities != crate::outcome::OUTCOME_UNKNOWN_CAPABILITY_V1
            {
                return Err(tonic::Status::failed_precondition(
                    "recovery credential namespace mismatch",
                ));
            }
            request.metadata_mut().insert(
                crate::caller_operation::CALLER_CAPABILITIES_METADATA_KEY,
                MetadataValue::from_static(crate::outcome::OUTCOME_UNKNOWN_CAPABILITY_V1),
            );
        }
        inject_authorization(&mut request, &authorization)?;
        inject_repository(&mut request, self.repository)?;
        inject_attempt_id(&mut request)?;
        if let Some(context) = crate::caller_operation::current_caller_operation() {
            if context.repository() != self.repository {
                return Err(tonic::Status::failed_precondition(
                    "managed operation repository mismatch",
                ));
            }
            request.metadata_mut().insert(
                crate::caller_operation::CALLER_CAPABILITIES_METADATA_KEY,
                MetadataValue::from_static(crate::outcome::OUTCOME_UNKNOWN_CAPABILITY_V1),
            );
        }
        Ok(request)
    }
}

#[derive(Clone, Debug)]
pub struct RequestLoggerService<S> {
    inner: S,
}

impl<S> Service<http::Request<Body>> for RequestLoggerService<S>
where
    S: Service<http::Request<Body>> + Send + Sync + Clone + 'static,
    S::Error: Error + Send + Sync + 'static,
    S::Future: Send,
    S::Response: std::fmt::Debug,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut core::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            lore_debug!("gRPC request: {req:?}");
            let start = Instant::now();
            let result = inner.call(req).await;
            let elapsed = start.elapsed().as_millis();
            match &result {
                Ok(response) => {
                    lore_debug!("gRPC response: {response:?} ({elapsed} ms)");
                }
                Err(err) => {
                    lore_debug!("gRPC failure: {err:?} ({elapsed} ms)");
                }
            }
            result
        })
    }
}

pub struct RequestLoggerLayer {}
impl<S> Layer<S> for RequestLoggerLayer
where
    S: Service<http::Request<Body>>,
{
    type Service = RequestLoggerService<S>;

    fn layer(&self, service: S) -> Self::Service {
        RequestLoggerService { inner: service }
    }
}

pub type Channel = RequestLoggerService<tonic::transport::Channel>;
pub type UnauthenticatedService = InterceptedService<Channel, CorrelationInterceptor>;
pub type AuthenticatedService = InterceptedService<Channel, AuthnInterceptor>;
pub type AuthorizedService = InterceptedService<Channel, AuthzInterceptor>;

const GRPC_PORT_DEFAULT: u16 = 41337;
const GRPCS_PORT_DEFAULT: u16 = 443;

type AuthUrl = String;
type UserIdentity = String;
type ResourceId = String;
/// Whether the authorization was obtained from credentials a caller supplied.
/// Keyed on for the same reason the connection is: a call that supplies none
/// must not be handed authorization obtained from another call's credential,
/// and vice versa. See `lore_transport::connection::FromSuppliedCredentials`.
type FromSuppliedCredentials = bool;

#[lore_macro::test_pub]
pub struct GRPCConnection {
    connection: Weak<Connection>,
    remote_url: Url,
    channel: parking_lot::RwLock<Channel>,
    auth: DashMap<(AuthUrl, UserIdentity, ResourceId, FromSuppliedCredentials), GRPCAuthRef>,
    reconnect: AtomicU32,
    reconnector: Semaphore,
}

impl GRPCConnection {
    pub(crate) fn selected_endpoint(&self) -> &str {
        self.remote_url.as_str()
    }
    /// Build a connection around an already-established channel, for tests that drive a
    /// storage client against a local server without going through the connect path.
    #[cfg(feature = "test-util")]
    pub fn for_test(remote_url: Url, channel: Channel) -> Self {
        Self {
            connection: Weak::new(),
            remote_url,
            channel: parking_lot::RwLock::new(channel),
            auth: DashMap::new(),
            reconnect: AtomicU32::new(1),
            reconnector: Semaphore::new(1),
        }
    }

    pub fn channel(&self) -> Channel {
        self.channel.read().clone()
    }

    pub async fn repository_authz(
        &self,
        auth_url: &str,
        identity: &str,
        repository: RepositoryId,
        credentials: &Arc<SuppliedCredentials>,
    ) -> GRPCAuthRef {
        let key = (
            auth_url.to_string(),
            identity.to_string(),
            repository.to_string(),
            credentials.from_supplied_credentials(),
        );

        if let Some(auth) = self.auth.get(&key) {
            return auth.clone();
        }

        let auth = GRPCAuth::new(
            auth_url,
            self.remote_url.host_str().unwrap_or_default(),
            identity,
            repository,
            credentials,
        )
        .await;

        self.auth.insert(key, auth.clone());
        auth
    }

    /// Obtains auth for a non-repository resource. The caller-supplied
    /// `resource` string is passed verbatim to the auth backend, scoping the
    /// resulting authorization token to that resource. The same string keys
    /// the connection-local cache.
    pub async fn custom_resource_authz(
        &self,
        auth_url: &str,
        identity: &str,
        resource: &str,
        credentials: &Arc<SuppliedCredentials>,
    ) -> GRPCAuthRef {
        let key = (
            auth_url.to_string(),
            identity.to_string(),
            resource.to_string(),
            credentials.from_supplied_credentials(),
        );

        if let Some(auth) = self.auth.get(&key) {
            return auth.clone();
        }

        let auth = GRPCAuth::new_for_custom_resource(
            auth_url,
            self.remote_url.host_str().unwrap_or_default(),
            identity,
            resource,
            credentials,
        )
        .await;

        self.auth.insert(key, auth.clone());
        auth
    }

    pub async fn reconnect(&self, reconnect_id: u32) -> Result<Channel, ProtocolError> {
        let _permit = self.reconnector.acquire().await;

        let current_reconnect_id = self.reconnect.load(Ordering::Relaxed);
        if current_reconnect_id == 0 {
            // Reconnection failed, give up
            return Err(ProtocolError::from(lore_base::error::Disconnected));
        }
        if current_reconnect_id > reconnect_id {
            // Something else completed the reconnection already
            return Ok(self.channel());
        }

        let mut retry_count = 1;
        let mut retry = crate::util::retry(
            RECONNECT_START_DELAY,
            RECONNECT_MAX_DELAY,
            RECONNECT_MAX_ATTEMPTS,
        );

        loop {
            lore_info!(
                "Reconnecting to {} attempt {} / {}",
                self.remote_url,
                retry_count,
                RECONNECT_MAX_ATTEMPTS
            );

            let start = Instant::now();

            match connect_to_endpoint(self.remote_url.as_str()).await {
                Ok(channel) => {
                    let new_reconnect_id = 1 + self.reconnect.fetch_add(1, Ordering::Relaxed);

                    lore_debug!(
                        "gRPC reconnection to {} complete in {}ms ({reconnect_id} -> {new_reconnect_id})",
                        self.remote_url,
                        start.elapsed().as_millis()
                    );

                    {
                        let mut lock = self.channel.write();
                        *lock = channel.clone();
                    }

                    lore_info!("Reconnected to {}", self.remote_url);

                    return Ok(channel);
                }
                Err(err) => {
                    lore_debug!("Reconnect attempt failed: {err}");
                    if !retry.wait().await {
                        lore_debug!("Reconnect attempts exhausted, giving up");
                        // Indicate that any pending commands entering this flow should give up
                        self.reconnect.store(0, Ordering::Relaxed);
                        if let Some(connection) = self.connection.upgrade() {
                            connection.stale.store(true, Ordering::Relaxed);
                        }
                        return Err(err);
                    }
                }
            }

            retry_count += 1;
        }
    }
}

#[allow(clippy::type_complexity)]
static CONNECTION_MAP: OnceLock<Mutex<Option<HashMap<String, Arc<RwLock<Weak<GRPCConnection>>>>>>> =
    OnceLock::new();

/// Clears the process-global gRPC connection cache. The cache holds a
/// `Weak<GRPCConnection>` per remote; if any strong reference to a
/// `GRPCConnection` (and the per-resource `GRPCAuth` token cache it carries)
/// survives a credential reset, `connect(reuse=true)` upgrades the `Weak` and
/// resurrects the stale connection — auth state included — for the rest of the
/// process's life. Dropping the map entries severs that resurrection path so
/// the next connect builds a fresh channel and a fresh auth exchange. Called
/// from `connection::drop_connections()` as part of the full transport reset.
pub async fn drop_grpc_connections() {
    let mut map = CONNECTION_MAP.get_or_init(|| Mutex::new(None)).lock().await;
    *map = None;
}

#[lore_macro::test_pub]
async fn lock_connection(remote_url: &Url) -> Arc<RwLock<Weak<GRPCConnection>>> {
    let remote_url = remote_url.to_string();
    let mut map = CONNECTION_MAP.get_or_init(|| Mutex::new(None)).lock().await;
    if map.is_none() {
        map.replace(HashMap::new());
    }
    let map = map.as_mut().unwrap();
    if let Some(connection) = map.get(&remote_url) {
        return connection.clone();
    }

    let connection = Arc::new(RwLock::new(Weak::new()));
    map.insert(remote_url, connection.clone());

    connection
}

const HTTP2_KEEP_ALIVE_INTERVAL: u64 = 30;
const HTTP2_KEEP_ALIVE_TIMEOUT: u64 = 20;

async fn connect_to_endpoint(remote: &str) -> Result<Channel, ProtocolError> {
    let mut endpoint = tonic::transport::Channel::from_shared(remote.to_string())
        .internal_with(|| format!("connect: {remote}"))?;

    let keep_alive_interval = std::env::var("LORE_HTTP2_KEEP_ALIVE_INTERVAL")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(HTTP2_KEEP_ALIVE_INTERVAL);
    let keep_alive_timeout = std::env::var("LORE_HTTP2_KEEP_ALIVE_TIMEOUT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(HTTP2_KEEP_ALIVE_TIMEOUT);
    endpoint = endpoint
        .http2_keep_alive_interval(Duration::from_secs(keep_alive_interval))
        .keep_alive_timeout(Duration::from_secs(keep_alive_timeout));

    if remote.starts_with("https://") {
        endpoint = endpoint
            .tls_config(
                ClientTlsConfig::new()
                    .assume_http2(true)
                    .with_webpki_roots()
                    .with_native_roots(),
            )
            .internal_with(|| format!("configuring TLS for {remote}"))?;
    }
    let user_agent = crate::user_agent();
    endpoint = endpoint
        .user_agent(user_agent)
        .internal_with(|| format!("setting user agent for {remote}"))?;

    lore_trace!("Set user agent to {user_agent}");

    endpoint = endpoint.connect_timeout(Duration::from_secs(GRPC_CONNECT_TIMEOUT_SECS));

    // Connect from a net-runtime task so the hyper/h2 driver tasks the
    // connection spawns are bound to the net runtime, isolated from compute and
    // file-I/O continuations on the core runtime.
    let channel = match lore_base::lore_spawn_net!(async move { endpoint.connect().await })
        .await
        .internal_with(|| format!("gRPC connection task to {remote}"))?
    {
        Ok(channel) => channel,
        Err(err) => {
            // An unreachable server is `Disconnected` so the reconnect paths
            // engage, but the transport error's detail is kept on the trace
            // rather than collapsed into a bare variant.
            let mut disconnected = ProtocolError::from(lore_base::error::Disconnected);
            disconnected.push_trace(lore_error_set::Location::with_context(
                file!(),
                line!(),
                column!(),
                Arc::from(format!("gRPC connection to {remote} failed: {err}")),
            ));
            return Err(disconnected);
        }
    };

    let channel = ServiceBuilder::new()
        .layer(RequestLoggerLayer {})
        .service(channel);

    Ok(channel)
}

pub async fn connect(
    connection: Weak<Connection>,
    remote_url: &str,
    reuse: bool,
) -> Result<Arc<GRPCConnection>, ProtocolError> {
    let parsed_url =
        Url::parse(remote_url).internal_with(|| format!("remote {remote_url} is invalid"))?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| ProtocolError::internal(format!("remote {remote_url} is invalid")))?;

    // Possible HTTPS schemes: urcs, grpcs, lores
    let (scheme, default_port) = if parsed_url.scheme().ends_with("s") {
        ("https", GRPCS_PORT_DEFAULT)
    } else {
        ("http", GRPC_PORT_DEFAULT)
    };

    // Use the LORE_GRPC_PORT env var as a temporary way to support
    // TLS-terminated LBs listening on a separate port in deployments
    let port = std::env::var("LORE_GRPC_PORT")
        .unwrap_or(parsed_url.port().unwrap_or(default_port).to_string());

    let remote = Url::parse(&format!("{scheme}://{host}:{port}"))
        .internal_with(|| format!("remote {remote_url} is invalid"))?;

    let map_lock = lock_connection(&remote).await;
    let connection_lock = if reuse {
        let lock = map_lock.write().await;
        if let Some(connection) = lock.upgrade()
            && connection.reconnect.load(Ordering::Relaxed) > 0
        {
            lore_trace!("gRPC reusing previous connection: {remote}");
            return Ok(connection);
        }
        lore_trace!("gRPC found no previous valid connection: {remote}");
        Some(lock)
    } else {
        lore_trace!("gRPC unique connection: {remote}");
        None
    };

    lore_debug!("gRPC connecting: {remote}");

    let start = Instant::now();
    let channel = connect_to_endpoint(remote.as_str()).await?;

    lore_debug!(
        "gRPC connected in {}ms: {remote}",
        start.elapsed().as_millis()
    );

    let connection = Arc::new(GRPCConnection {
        connection,
        remote_url: remote,
        channel: parking_lot::RwLock::new(channel),
        auth: DashMap::new(),
        reconnect: AtomicU32::new(1),
        reconnector: Semaphore::new(1),
    });

    if let Some(mut lock) = connection_lock {
        *lock = Arc::downgrade(&connection);
        lore_trace!("Stored established gRPC connection");
    }

    Ok(connection)
}

/// The canonical type URL a `google.rpc.RetryInfo` is packed under.
const RETRY_INFO_TYPE_URL: &str = "type.googleapis.com/google.rpc.RetryInfo";

/// The `google.rpc.Status` carried in the `grpc-status-details-bin` trailer.
///
/// Only `details` is transcribed. prost skips fields a message does not declare,
/// and the trailer's `code` and `message` duplicate what the gRPC status line
/// already carries — this decoder reads neither. Hand-written for the same two
/// reasons the server hand-writes the matching encoder
/// (`lore-server/src/event_relay/retry_info.rs`): `protoc` is optional in this
/// workspace, and this is a decade-frozen schema of three fields.
#[derive(Clone, PartialEq, prost::Message)]
struct RpcStatusDetails {
    #[prost(message, repeated, tag = "3")]
    details: Vec<prost_types::Any>,
}

/// `google.rpc.RetryInfo`.
#[derive(Clone, PartialEq, prost::Message)]
struct RetryInfo {
    #[prost(message, optional, tag = "1")]
    retry_delay: Option<prost_types::Duration>,
}

/// The server's requested retry delay, clamped to this client's own ceiling.
///
/// `None` whenever there is no usable hint, and that covers more than an absent
/// trailer. **The `details` field on this fork is not reliably a
/// `google.rpc.Status`**: several handlers in `lore-server`'s `grpc::mod` put
/// their own opaque bytes there instead, which the admission gate's encoder
/// records as `PIN(WP-119)`. So arbitrary bytes have to decode to "no hint"
/// rather than to a wrong duration or a panic, and every step below is fallible
/// on purpose — a bad decode, a missing detail, a missing delay, or a negative
/// one all return `None` and leave the caller on its own schedule.
///
/// The clamp to [`RETRY_MAX_BACKOFF`] is what keeps a remote from setting this
/// client's wait: a server asking for an hour gets the same ten seconds a server
/// asking for ten does. The hint can only ever move a wait *up to* the ceiling
/// this client already shipped, never past it.
///
/// `pub` only so `lore-server`'s load proof and this crate's own retry-budget
/// suite can drive it from outside; `handle_error` is the sole production
/// caller. Hidden from the rendered docs to keep it off the crate's advertised
/// surface.
#[doc(hidden)]
pub fn retry_delay_hint(status: &Status) -> Option<Duration> {
    use prost::Message as _;

    let trailer = status.details();
    if trailer.is_empty() {
        return None;
    }

    let decoded = RpcStatusDetails::decode(trailer).ok()?;
    let any = decoded
        .details
        .iter()
        .find(|any| any.type_url == RETRY_INFO_TYPE_URL)?;
    let delay = RetryInfo::decode(&any.value[..]).ok()?.retry_delay?;

    // A `google.protobuf.Duration` is signed. A negative one is not a delay this
    // client can honour, and saturating it to zero would silently turn a
    // malformed hint into "retry immediately" — the one direction that makes
    // things worse for a server already refusing.
    let seconds = u64::try_from(delay.seconds).ok()?;
    let nanos = u32::try_from(delay.nanos).ok()?;

    // Saturating rather than `Duration::new`, which panics on overflow.
    let hint = Duration::from_secs(seconds).saturating_add(Duration::from_nanos(u64::from(nanos)));
    Some(hint.min(RETRY_MAX_BACKOFF))
}

/// Wait out one retry attempt, never returning sooner than the server asked.
///
/// The wait is `max(this client's own next backoff step, hint)`, and it costs
/// **exactly one attempt** — the hint changes how long an attempt waits, never
/// how many attempts remain. [`crate::util::Retry`] owns the sleeping, the
/// jitter and the counting; all this adds is the remainder, and only when the
/// step it already slept fell short of the hint. With `hint` of `None` that
/// remainder is never computed and the behaviour is exactly `retry.wait()`.
///
/// Taking the maximum rather than the hint is deliberate in both directions. The
/// hint is a floor the server is entitled to set, so a 50 ms opening step must
/// not race ahead of it; and the client's own late-schedule steps are a ceiling
/// the server is not entitled to lower, so a small hint cannot pull an
/// exhausted-looking client back into hammering.
///
/// An exhausted budget returns `false` without sleeping the remainder: there is
/// no attempt left for it to belong to.
///
/// **This is the unbudgeted primitive.** It knows how long one attempt waits and
/// nothing about how many seconds the RPC has left; [`RetryBudget::wait`] is
/// what production calls, and it gates this one against
/// [`RETRY_WALL_CLOCK_BUDGET`]. Driving this function directly measures the
/// backoff schedule, not the shipped policy.
///
/// `pub` and `#[doc(hidden)]` for the same reason as [`retry_delay_hint`]: it is
/// a test seam, not advertised surface.
#[doc(hidden)]
pub async fn wait_with_hint(retry: &mut crate::util::Retry, hint: Option<Duration>) -> bool {
    let started = tokio::time::Instant::now();
    if !retry.wait().await {
        return false;
    }
    if let Some(hint) = hint
        && let Some(remainder) = hint.checked_sub(started.elapsed())
    {
        tokio::time::sleep(remainder).await;
    }
    true
}

/// Encode a missing address as `FAILED_PRECONDITION` carrying it in the status
/// details.
///
/// The code states that the request cannot be served in the peer's current
/// state, leaving `NOT_FOUND` to name an absent object alone. The details carry
/// the address, which [`address_not_found_details`] reads back.
pub fn address_not_found_status(error: &AddressNotFound, message: impl Into<String>) -> Status {
    Status::with_details(
        tonic::Code::FailedPrecondition,
        message,
        Bytes::copy_from_slice(&error.address),
    )
}

/// Recover the address a peer attached with [`address_not_found_status`].
///
/// Details of any other length read as absent, so an address is reconstructed
/// only from one this side can name in full.
pub(crate) fn address_not_found_details(status: &Status) -> Option<AddressNotFound> {
    Some(AddressNotFound {
        address: status.details().try_into().ok()?,
    })
}

/// Decide whether a failed RPC is worth another attempt, and wait if it is.
///
/// **Only `RESOURCE_EXHAUSTED` is retried here, and that is unchanged.**
/// [`retry_delay_hint`] does not look at the status code, so a hint would be
/// honoured on any code this arm grew to cover — but growing it is a separate
/// decision with a separate cost. `UNAVAILABLE` in particular is not retryable
/// from this seam: it can follow a request that already reached the server, and
/// re-issuing one of those is the redispatch that [`with_reconnect_classified`]
/// exists to refuse. A hint in the trailer is a request for patience, never a
/// warrant to send a mutation twice.
///
/// `retry` carries the RPC's wall-clock deadline as well as its attempt count,
/// so a hint too long to fit in what remains ends the loop here rather than
/// stretching it. The status returned is the one the server actually sent,
/// whichever bound ran out — a caller cannot tell the two apart, and does not
/// need to.
async fn handle_error(retry: &mut RetryBudget, status: Status) -> Result<(), ProtocolError> {
    match status.code() {
        tonic::Code::ResourceExhausted => {
            let hint = retry_delay_hint(&status);
            if !retry.wait(hint).await {
                return Err(ProtocolError::from(status));
            }
        }
        _ => return Err(ProtocolError::from(status)),
    }
    Ok(())
}

#[allow(clippy::unused_async)]
pub async fn storage_client(
    connection: Arc<GRPCConnection>,
    auth_url: &str,
    identity: &str,
    _partition: Partition,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Storage>, ProtocolError> {
    lore_trace!("Connecting gRPC storage client");

    let storage_client = storage_client::StorageService::new(connection.clone());

    let storage = GRPCStorage {
        connection,
        client: storage_client,
        auth_url: auth_url.to_string(),
        identity: identity.to_string(),
        credentials: credentials.clone(),
        session_counter: std::sync::atomic::AtomicU32::new(1),
        sessions: DashMap::new(),
    };

    lore_trace!("Connecting gRPC storage client complete");

    Ok(Arc::new(storage))
}

pub async fn revision_client(
    connection: Arc<GRPCConnection>,
    auth_url: &str,
    identity: &str,
    repository: RepositoryId,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Revision>, ProtocolError> {
    lore_trace!("Creating gRPC revision client");

    let revision_client = revision_client::RevisionService::new(
        connection.channel(),
        repository,
        connection
            .repository_authz(auth_url, identity, repository, credentials)
            .await,
    );

    let revision = GRPCRevision {
        connection,
        client: RwLock::new(revision_client),
        auth_url: auth_url.to_string(),
        identity: identity.to_string(),
        credentials: credentials.clone(),
        repository,
    };

    lore_trace!("Connecting gRPC revision client complete");

    Ok(Arc::new(revision))
}

pub async fn admin_client(
    connection: Arc<GRPCConnection>,
    auth_url: &str,
    identity: &str,
    repository: RepositoryId,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Admin>, ProtocolError> {
    lore_trace!("Creating gRPC admin client");

    let admin_client = admin_client::AdminService::new(
        connection.channel(),
        repository,
        connection
            .repository_authz(auth_url, identity, repository, credentials)
            .await,
    );

    let admin = GRPCAdmin {
        connection,
        client: RwLock::new(admin_client),
        auth_url: auth_url.to_string(),
        identity: identity.to_string(),
        credentials: credentials.clone(),
        repository,
    };

    lore_trace!("Connecting gRPC admin client complete");

    Ok(Arc::new(admin))
}

pub async fn repository_client(
    connection: Arc<GRPCConnection>,
    auth_url: &str,
    identity: &str,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Repository>, ProtocolError> {
    lore_trace!("Connecting gRPC repository client");

    let repository_client = repository_client::RepositoryService::new(
        connection.channel(),
        connection
            .repository_authz(auth_url, identity, RepositoryId::default(), credentials)
            .await,
    );

    let repository = GRPCRepository {
        connection,
        client: RwLock::new(repository_client),
        auth_url: auth_url.to_string(),
        identity: identity.to_string(),
        credentials: credentials.clone(),
    };

    lore_trace!("Connecting gRPC repository client complete");

    Ok(Arc::new(repository))
}

pub async fn lock_client(
    connection: Arc<GRPCConnection>,
    auth_url: &str,
    identity: &str,
    repository: RepositoryId,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Lock>, ProtocolError> {
    lore_trace!("Connecting gRPC lock client");

    let lock_client = lock_client::LockService::new(
        connection.channel(),
        repository,
        connection
            .repository_authz(auth_url, identity, repository, credentials)
            .await,
    );

    let lock = GRPCLock {
        connection,
        repository,
        client: RwLock::new(lock_client),
        auth_url: auth_url.to_string(),
        identity: identity.to_string(),
        credentials: credentials.clone(),
    };

    lore_trace!("Connecting gRPC lock client complete");

    Ok(Arc::new(lock))
}

pub async fn domain_operations_client(
    connection: Arc<GRPCConnection>,
    auth_url: &str,
    identity: &str,
    repository: RepositoryId,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn DomainOperations>, ProtocolError> {
    lore_trace!("Connecting gRPC domain-operation receipt client");

    let receipt_client = domain_operation_client::DomainOperationService::new(
        connection.channel(),
        repository,
        connection
            .repository_authz(auth_url, identity, repository, credentials)
            .await,
    );

    let domain_operations = GRPCDomainOperations {
        connection,
        client: RwLock::new(receipt_client),
        auth_url: auth_url.to_string(),
        identity: identity.to_string(),
        credentials: credentials.clone(),
        repository,
    };

    lore_trace!("Connecting gRPC domain-operation receipt client complete");

    Ok(Arc::new(domain_operations))
}

pub fn environment_client(
    connection: Arc<GRPCConnection>,
) -> Result<Arc<dyn Environment>, ProtocolError> {
    lore_trace!("Connecting gRPC environment client");

    let environment_client = environment_client::EnvironmentService::new(connection.channel());

    let environment = GRPCEnvironment {
        connection,
        client: RwLock::new(environment_client),
    };

    lore_trace!("Connecting gRPC environment client complete");

    Ok(Arc::new(environment))
}

#[allow(clippy::too_many_arguments)]
pub async fn storage(
    connection: Weak<Connection>,
    remote_url: &str,
    auth_url: &str,
    identity: &str,
    partition: Partition,
    index: usize,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Storage>, ProtocolError> {
    // We open multiple storage connections, only reuse previous connections for the first
    let reuse = index == 0;
    let connection = connect(connection, remote_url, reuse).await?;
    storage_client(connection, auth_url, identity, partition, credentials).await
}

pub async fn revision(
    connection: Weak<Connection>,
    remote_url: &str,
    auth_url: &str,
    identity: &str,
    repository: RepositoryId,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Revision>, ProtocolError> {
    let connection = connect(connection, remote_url, true).await?;
    revision_client(connection, auth_url, identity, repository, credentials).await
}

pub async fn repository(
    connection: Weak<Connection>,
    remote_url: &str,
    auth_url: &str,
    identity: &str,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Repository>, ProtocolError> {
    let connection = connect(connection, remote_url, true).await?;
    repository_client(connection, auth_url, identity, credentials).await
}

pub async fn lock(
    connection: Weak<Connection>,
    remote_url: &str,
    auth_url: &str,
    identity: &str,
    repository: RepositoryId,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Lock>, ProtocolError> {
    let connection = connect(connection, remote_url, true).await?;
    lock_client(connection, auth_url, identity, repository, credentials).await
}

pub async fn admin(
    connection: Weak<Connection>,
    remote_url: &str,
    auth_url: &str,
    identity: &str,
    repository: RepositoryId,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn Admin>, ProtocolError> {
    let connection = connect(connection, remote_url, true).await?;
    admin_client(connection, auth_url, identity, repository, credentials).await
}

pub async fn environment(
    connection: Weak<Connection>,
    remote_url: &str,
) -> Result<Arc<dyn Environment>, ProtocolError> {
    let connection = connect(connection, remote_url, true).await?;
    environment_client(connection)
}

pub async fn domain_operations(
    connection: Weak<Connection>,
    remote_url: &str,
    auth_url: &str,
    identity: &str,
    repository: RepositoryId,
    credentials: &Arc<SuppliedCredentials>,
) -> Result<Arc<dyn DomainOperations>, ProtocolError> {
    let connection = connect(connection, remote_url, true).await?;
    domain_operations_client(connection, auth_url, identity, repository, credentials).await
}

/// Counts one in-flight request for as long as the guard is alive.
///
/// **Bind it to a name.** `let _ = RequestScopedCounter::new(..)` drops the guard at the end of
/// that statement, so the counter increments and decrements before the request is even built and
/// the gauge reads zero for every call. `let _counter = ` is what holds it for the scope. Every
/// call site in this module but one used the first form until WP-120 — twelve of thirteen, across
/// the admin, lock and revision clients — so the gauge they fed could only ever read zero. The
/// single correct one in `revision_client` is why the bug survived: the pattern was there to copy
/// and the wrong form was the one that got copied.
struct RequestScopedCounter {
    counter: Arc<AtomicU64>,
}

impl RequestScopedCounter {
    pub fn new(counter: Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, std::sync::atomic::Ordering::Release);
        RequestScopedCounter { counter }
    }
}

impl Drop for RequestScopedCounter {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}

struct GRPCAdmin {
    connection: Arc<GRPCConnection>,
    client: RwLock<admin_client::AdminService>,
    auth_url: String,
    identity: String,
    credentials: Arc<SuppliedCredentials>,
    repository: RepositoryId,
}

impl GRPCAdmin {
    async fn reconnect(&self, reconnect_id: u32) -> Result<(), ProtocolError> {
        let channel = self.connection.reconnect(reconnect_id).await?;

        let mut lock = self.client.write().await;
        *lock = admin_client::AdminService::new(
            channel,
            self.repository,
            self.connection
                .repository_authz(
                    self.auth_url.as_str(),
                    self.identity.as_str(),
                    self.repository,
                    &self.credentials,
                )
                .await,
        );

        Ok(())
    }
}

#[async_trait]
impl Admin for GRPCAdmin {
    /// `with_reconnect`, not `with_reconnect_classified`.
    ///
    /// The reconnect is not optional: `handle_error` retries only
    /// `ResourceExhausted`, so a dropped channel surfaces as
    /// `ProtocolError::Disconnected` and the client's own `grpc_retry` never sees
    /// it. Without this wrapper `server_info` would be the one `Admin` verb that
    /// fails permanently after a drop on a long-lived connection while
    /// `obliterate` recovers.
    ///
    /// The *classified* wrapper is what this does not need. That one decides
    /// whether an interrupted dispatch may be replayed; `ServerInfo` mutates
    /// nothing, so there is no outcome to classify and no `GrpcRpc` variant or
    /// replay class to add.
    async fn server_info(&self) -> Result<ServerInfo, ProtocolError> {
        with_reconnect(
            &self.connection,
            || async { self.client.read().await.server_info().await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn obliterate(&self, address: Address) -> Result<(), ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::AdminObliterate,
            || async { self.client.read().await.obliterate(address).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }
}

/// Domain-operation receipt rail over gRPC (CR-029, WP-120).
struct GRPCDomainOperations {
    connection: Arc<GRPCConnection>,
    client: RwLock<domain_operation_client::DomainOperationService>,
    auth_url: String,
    identity: String,
    credentials: Arc<SuppliedCredentials>,
    repository: RepositoryId,
}

impl GRPCDomainOperations {
    async fn reconnect(&self, reconnect_id: u32) -> Result<(), ProtocolError> {
        let channel = self.connection.reconnect(reconnect_id).await?;

        let mut lock = self.client.write().await;
        *lock = domain_operation_client::DomainOperationService::new(
            channel,
            self.repository,
            self.connection
                .repository_authz(
                    self.auth_url.as_str(),
                    self.identity.as_str(),
                    self.repository,
                    &self.credentials,
                )
                .await,
        );

        Ok(())
    }
}

#[async_trait]
impl DomainOperations for GRPCDomainOperations {
    /// Reconnects and reissues, which is safe here for a reason it is not safe for the mutation
    /// this lookup asks about. Not because the lookup writes nothing — one that finds an expired
    /// `PREPARED` row terminalizes it — but because whatever it settles, it settles the same way
    /// every time. A second lookup after a lost channel finds the row already committed and
    /// returns the first one's answer.
    async fn receipt_get(
        &self,
        query: &DomainReceiptQuery,
    ) -> Result<DomainReceipt, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::DomainOperationReceiptGet,
            || async { self.client.read().await.receipt_get(query).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    /// Retryable for the same reason its sibling is: whatever the lookup settles, it settles the
    /// same way every time.
    async fn attempt_receipt_get(
        &self,
        attempt: &AttemptId,
    ) -> Result<DomainAttemptReceipt, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::DomainOperationAttemptReceiptGet,
            || async { self.client.read().await.attempt_receipt_get(attempt).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }
}

/// Storage protocol implementation over gRPC
#[lore_macro::test_pub]
struct GRPCStorage {
    connection: Arc<GRPCConnection>,
    client: storage_client::StorageService,
    /// Auth URL for token exchange.
    auth_url: String,
    /// Identity for token exchange.
    identity: String,
    /// The credentials supplied for the call in progress, shared so a reconnect
    /// re-authorizes with what the newest call supplied.
    credentials: Arc<SuppliedCredentials>,
    /// Client-local session counter for monotonic session IDs.
    session_counter: std::sync::atomic::AtomicU32,
    /// Client-local session map: `session_id` -> context for metadata injection.
    /// Built at `session_start` time with the auth token, reused without lock reads.
    sessions: DashMap<u32, Arc<storage_client::GrpcSessionContext>>,
}

/// Bound on connection-level reconnect attempts for one operation.
///
/// `GRPCConnection::reconnect` gives up permanently once its own connect retries are exhausted,
/// but that only covers a remote it cannot reach. One that accepts connections while every RPC
/// on them fails reconnects successfully every time, so the driving loop needs its own bound.
#[lore_macro::test_pub]
const MAX_RECONNECTS_PER_OP: usize = 3;

/// Run an operation, reconnecting and reissuing if it reports the channel is gone.
///
/// The counterpart of the QUIC client's `send_with_reconnect`. Only `Disconnected` provokes a
/// reconnect: anything else the remote answers is its verdict on this request, and the stream
/// layer has already reissued whatever was recoverable there.
///
/// The epoch is read per attempt, not once. `GRPCConnection::reconnect` treats an epoch older
/// than the current one as "somebody else already reconnected" and returns without doing
/// anything — correct for a concurrent caller, but for a *later attempt by the same caller* it
/// means no reconnect, no backoff, and no route to the permanent give-up that only the connect
/// loop sets. Bounding the attempts covers the remaining case: a remote that accepts
/// connections while failing every RPC on them reconnects successfully every round.
///
/// The rebuild is boxed. It runs only after a lost channel, and inline it would make every
/// request's future as large as a reconnect.
#[lore_macro::test_pub]
async fn with_reconnect<T, Op, OpFut, Rebuild, RebuildFut>(
    connection: &GRPCConnection,
    op: Op,
    rebuild: Rebuild,
) -> Result<T, ProtocolError>
where
    Op: Fn() -> OpFut,
    OpFut: Future<Output = Result<T, ProtocolError>>,
    Rebuild: Fn(u32) -> RebuildFut,
    RebuildFut: Future<Output = Result<(), ProtocolError>>,
{
    for _ in 0..MAX_RECONNECTS_PER_OP {
        let reconnect_id = connection.reconnect.load(Ordering::Relaxed);
        match op().await {
            Err(ProtocolError::Disconnected(_)) => Box::pin(rebuild(reconnect_id)).await?,
            result => return result,
        }
    }
    Err(ProtocolError::from(lore_base::error::Disconnected))
}

/// Run one gRPC call under its replay class (WP-120 Phase 3).
///
/// Every call site names its RPC, and [`grpc_replay_class`] decides from that whether losing
/// the channel is something this layer may paper over. A read is reissued exactly as before. A
/// mutation is not: the request went out, its answer did not come back, and no amount of
/// reconnecting turns that into knowledge of what the server did.
///
/// **The mutable branch is fail-closed, and that is a deliberate cost.** gRPC gives this layer
/// no dispatch state — the QUIC client knows whether bytes reached the wire because it writes
/// them itself, and there is no equivalent here. So a mutation that failed *before* leaving the
/// client is reported the same as one whose answer was lost. Reporting the safe direction as
/// the ambiguous one costs availability; reporting the ambiguous one as retryable costs a
/// duplicate mutation, and the contract is explicit that a retry needs positive proof of
/// non-dispatch rather than the absence of proof of dispatch. The one place that proof does
/// exist on this transport is the streaming send in `storage_client`, which knows its payload
/// came back unsent, and it uses it.
///
/// The attempt id is minted before the call, not after the failure, so it names the attempt the
/// server would have recorded rather than the moment this client noticed.
#[lore_macro::test_pub]
async fn with_reconnect_classified<T, Op, OpFut, Rebuild, RebuildFut>(
    connection: &GRPCConnection,
    rpc: GrpcRpc,
    op: Op,
    rebuild: Rebuild,
) -> Result<T, ProtocolError>
where
    Op: Fn() -> OpFut,
    OpFut: Future<Output = Result<T, ProtocolError>>,
    Rebuild: Fn(u32) -> RebuildFut,
    RebuildFut: Future<Output = Result<(), ProtocolError>>,
{
    if let Some(recovery) = crate::caller_operation::current_caller_recovery()
        && (recovery.endpoint
            != crate::caller_operation::canonical_endpoint(connection.remote_url.as_str())?
            || grpc_replay_class(rpc) != ReplayClass::ReadRetryable)
    {
        return Err(ProtocolError::internal("recovery dispatch scope mismatch"));
    }
    match grpc_replay_class(rpc) {
        ReplayClass::ReadRetryable => with_reconnect(connection, op, rebuild).await,
        ReplayClass::MutableNoReplay => {
            if crate::caller_operation::current_caller_operation().is_some()
                && !matches!(
                    rpc,
                    GrpcRpc::RevisionBranchPush
                        | GrpcRpc::RevisionBranchCreate
                        | GrpcRpc::LockLock
                        | GrpcRpc::LockAdminLock
                        | GrpcRpc::LockUnlock
                        | GrpcRpc::LockForceUnlock
                        | GrpcRpc::StorageVerify
                        | GrpcRpc::StorageMutableStore
                        | GrpcRpc::StorageMutableCompareAndSwap
                )
            {
                return Err(ProtocolError::internal(
                    "this mutation is not supported by managed caller adoption",
                ));
            }
            // Reuse the attempt this dispatch is already running under, and mint only when there
            // is none. A caller that journaled an id before calling in — which is what a client
            // must do to be able to reconcile a lost answer at all — would otherwise have that id
            // shadowed here, and the receipt the server filed would be keyed to an identity the
            // caller never wrote down.
            let attempt = crate::outcome::current_dispatch_attempt().unwrap_or_else(AttemptId::new);
            // Scoped around the dispatch so the interceptor stamps this attempt onto the
            // request. The id the server persists is therefore the same one this client names in
            // the error it raises when the answer never arrives, which is the whole point: a
            // reconciler looks the receipt up under the identity it already journaled.
            match crate::caller_operation::with_transport_endpoint(
                connection.remote_url.to_string(),
                crate::outcome::with_dispatch_attempt(attempt, op()),
            )
            .await
            {
                Err(error)
                    if answer_is_not_settled(&error)
                        || !not_prepared_proof_holds(&error, &attempt) =>
                {
                    Err(outcome_unknown(rpc.wire_name(), &attempt))
                }
                result => result,
            }
        }
    }
}

/// Whether a failed mutation's error leaves the server's answer unsettled.
///
/// Two shapes reach here, and neither is a refusal:
///
/// - `Disconnected`, which says the channel carrying the request is gone.
/// - An `Internal` carrying [`crate::error::answer_lost_code`]'s proof, which says `tonic`
///   failed the *call* — a mid-flight stream reset, a hyper cancellation, an expired
///   `grpc-timeout`, or an h2 protocol error. Before this existed those three codes funnelled
///   into a plain `Internal` and read to the caller exactly like a server refusal, so a reset
///   in the middle of a lock release escalated to a force-release on a maybe.
///
/// One predicate, consulted once, rather than a second arm on the match above: the classifier
/// property is orthogonal to which error variant carries it, and this crate has already been
/// bitten by per-branch guards that later arms forgot to repeat.
fn answer_is_not_settled(error: &ProtocolError) -> bool {
    matches!(error, ProtocolError::Disconnected(_))
        || crate::error::answer_lost_code(error).is_some()
}

/// Whether a server's not-prepared proof, if the error carries one, settles this attempt.
///
/// An error without the proof is an ordinary refusal and this answers `true`. With the proof it
/// answers `true` only when the proof names this attempt and this process sent the attempt
/// exactly once. The proof is the server's word about the copy it refused; a second copy (a
/// retry loop, or one id scoped across several dispatches) may have reached another replica and
/// been prepared there, so the attempt then stays unknown.
#[lore_macro::test_pub]
pub(crate) fn not_prepared_proof_holds(error: &ProtocolError, attempt: &AttemptId) -> bool {
    match crate::error::not_prepared_attempt(error) {
        None => true,
        Some(marked) => {
            marked == attempt.as_uuid() && crate::outcome::dispatch_send_count(attempt) == 1
        }
    }
}

impl GRPCStorage {
    /// Look up the cached session context.
    ///
    /// Shared rather than cloned: the context carries the session's auth token, and every
    /// consumer only borrows it, so cloning per operation would copy the token for each fragment
    /// on a bulk path like clone or sync.
    fn session_context(
        &self,
        session_id: u32,
    ) -> Result<Arc<storage_client::GrpcSessionContext>, ProtocolError> {
        self.sessions
            .get(&session_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| ProtocolError::internal("gRPC session not found"))
    }

    /// Storage needs no client rebuild: `StorageService` resolves the channel when it opens a
    /// stream, so a reconnected channel is picked up by the next rotation on its own.
    ///
    /// **The stream-backed verbs must not use the fail-closed unary policy (WP-120).** `Get`,
    /// `GetMetadata`, `Put` and `Copy` go through `StorageService`'s stream cache, which is the
    /// one layer on this transport that knows a request's dispatch state: it returns
    /// [`ProtocolError::OutcomeUnknown`] for a mutation it handed to the stream task, and
    /// `Disconnected` only where it holds positive proof the payload was never sent. Wrapping
    /// that in [`with_reconnect_classified`] would turn real non-dispatch proof back into an
    /// unknown outcome — a false unknown — and would drop the reconnect that the proof exists
    /// to authorise. So `Disconnected` here is reconnected and reissued for either replay
    /// class, and an unknown passes through untouched, because [`with_reconnect`] only ever
    /// matches `Disconnected`.
    ///
    /// This is exactly why the split exists: `Verify`, `MutableStore`, `MutableCompareAndSwap`,
    /// `Query` and `MutableLoad` are plain unary RPCs with no such proof, and they go through
    /// [`Self::with_reconnect_classified_unary`] instead.
    ///
    /// The RPC is still named at every call site. It costs nothing at runtime and keeps the
    /// stream-backed verbs inside the same no-wildcard classification table as everything else,
    /// so a new one cannot be added here without deciding its replay class.
    async fn with_reconnect_dispatch_aware<T, Op, Fut>(
        &self,
        rpc: GrpcRpc,
        op: Op,
    ) -> Result<T, ProtocolError>
    where
        Op: Fn() -> Fut,
        Fut: Future<Output = Result<T, ProtocolError>>,
    {
        // Read for its exhaustiveness, not its value: an unclassified verb does not compile.
        let _class = grpc_replay_class(rpc);
        with_reconnect(&self.connection, op, |reconnect_id| async move {
            self.connection.reconnect(reconnect_id).await.map(|_| ())
        })
        .await
    }

    /// The unary storage verbs, which have no dispatch state of their own.
    ///
    /// `Verify`, `MutableStore`, `MutableCompareAndSwap`, `Query` and `MutableLoad` are single
    /// RPCs rather than stream items, so nothing below this point can say whether a request
    /// that lost its channel was sent. They take the fail-closed policy: reads reissue,
    /// mutations become [`ProtocolError::OutcomeUnknown`] rather than being sent again.
    async fn with_reconnect_classified_unary<T, Op, Fut>(
        &self,
        rpc: GrpcRpc,
        op: Op,
    ) -> Result<T, ProtocolError>
    where
        Op: Fn() -> Fut,
        Fut: Future<Output = Result<T, ProtocolError>>,
    {
        with_reconnect_classified(&self.connection, rpc, op, |reconnect_id| async move {
            self.connection.reconnect(reconnect_id).await.map(|_| ())
        })
        .await
    }
}

#[async_trait]
impl Storage for GRPCStorage {
    async fn session_start(
        &self,
        partition: Partition,
        correlation_id: &str,
    ) -> Result<u32, ProtocolError> {
        let auth = self
            .connection
            .repository_authz(&self.auth_url, &self.identity, partition, &self.credentials)
            .await;
        let token = auth.read().authorization_token.clone();

        let session_id = self
            .session_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.sessions.insert(
            session_id,
            Arc::new(storage_client::GrpcSessionContext {
                partition,
                correlation_id: correlation_id.to_string(),
                auth_token: token,
            }),
        );
        Ok(session_id)
    }

    async fn session_stop(&self, session_id: u32) -> Result<(), ProtocolError> {
        self.sessions.remove(&session_id);
        self.client.remove_session_streams(session_id);
        Ok(())
    }

    async fn get(
        &self,
        session_id: u32,
        address: &Address,
    ) -> Result<(Fragment, Bytes), ProtocolError> {
        let ctx = self.session_context(session_id)?;
        self.with_reconnect_dispatch_aware(GrpcRpc::StorageGet, || {
            self.client.get(session_id, &ctx, address)
        })
        .await
    }

    async fn get_metadata(
        &self,
        session_id: u32,
        address: &Address,
    ) -> Result<Fragment, ProtocolError> {
        let ctx = self.session_context(session_id)?;
        self.with_reconnect_dispatch_aware(GrpcRpc::StorageGetMetadata, || {
            self.client.get_metadata(session_id, &ctx, address)
        })
        .await
    }

    async fn get_resolved(
        &self,
        session_id: u32,
        key: &Hash,
        context: &Context,
        flags: u32,
    ) -> Result<(Hash, Fragment, Bytes), ProtocolError> {
        let ctx = self.session_context(session_id)?;
        self.client
            .get_resolved(session_id, &ctx, key, context, flags)
            .await
    }

    async fn put_resolved(
        &self,
        session_id: u32,
        key: &Hash,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
    ) -> Result<(), ProtocolError> {
        let ctx = self.session_context(session_id)?;
        self.client
            .put_resolved(session_id, &ctx, key, address, fragment, payload)
            .await
    }

    async fn put(
        &self,
        session_id: u32,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
    ) -> Result<(), ProtocolError> {
        let ctx = self.session_context(session_id)?;
        self.with_reconnect_dispatch_aware(GrpcRpc::StoragePut, || {
            self.client
                .put(session_id, &ctx, address, fragment, payload.clone())
        })
        .await
    }

    async fn query(&self, session_id: u32, address: &[Address]) -> Result<Bytes, ProtocolError> {
        let ctx = self.session_context(session_id)?;
        self.with_reconnect_classified_unary(GrpcRpc::StorageQuery, || {
            self.client.query(&ctx, address)
        })
        .await
    }

    async fn verify(
        &self,
        session_id: u32,
        address: &Address,
        heal: bool,
    ) -> Result<VerifyResult, ProtocolError> {
        let ctx = self.session_context(session_id)?;
        // boxed: the classified future is over 16 KB on Windows
        Box::pin(
            self.with_reconnect_classified_unary(GrpcRpc::StorageVerify, || {
                self.client.verify(&ctx, address, heal)
            }),
        )
        .await
    }

    async fn copy(
        &self,
        session_id: u32,
        source_partition: Partition,
        source_address: Address,
        target_context: Context,
    ) -> Result<(), ProtocolError> {
        let ctx = self.session_context(session_id)?;
        self.with_reconnect_dispatch_aware(GrpcRpc::StorageCopy, || {
            self.client.copy(
                session_id,
                &ctx,
                source_partition,
                source_address,
                target_context,
            )
        })
        .await
    }

    async fn mutable_load(
        &self,
        session_id: u32,
        key: &Hash,
        key_type: KeyType,
    ) -> Result<Hash, ProtocolError> {
        let ctx = self.session_context(session_id)?;
        self.with_reconnect_classified_unary(GrpcRpc::StorageMutableLoad, || {
            self.client.mutable_load(&ctx, key, key_type)
        })
        .await
    }

    async fn mutable_store(
        &self,
        session_id: u32,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), ProtocolError> {
        let ctx = self.session_context(session_id)?;
        // boxed: the classified future is over 16 KB on Windows
        Box::pin(
            self.with_reconnect_classified_unary(GrpcRpc::StorageMutableStore, || {
                self.client.mutable_store(&ctx, key, value, key_type)
            }),
        )
        .await
    }

    async fn mutable_compare_and_swap(
        &self,
        session_id: u32,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<Hash, ProtocolError> {
        let ctx = self.session_context(session_id)?;
        // boxed: the classified future is over 16 KB on Windows
        Box::pin(self.with_reconnect_classified_unary(
            GrpcRpc::StorageMutableCompareAndSwap,
            || {
                self.client
                    .mutable_compare_and_swap(&ctx, key, expected, value, key_type)
            },
        ))
        .await
    }

    /// Constant, deliberately.
    ///
    /// A gRPC storage session is held in this client's own `sessions` map and re-registered on
    /// reconnect, so a session id here does not expire with a connection generation the way a
    /// QUIC one does. Reporting a moving epoch would make the session layer re-run
    /// `session_start` on a transport that never needed it, which is the QUIC lifecycle
    /// leaking into a path that does not share it.
    fn connection_epoch(&self) -> u32 {
        GRPC_STATIC_SESSION_EPOCH
    }

    /// Constant, for the same reason [`Storage::connection_epoch`] is: this client's sessions do
    /// not belong to a connection generation, so there is no generation for one to stop
    /// belonging to.
    fn connection_generation(&self) -> u32 {
        GRPC_STATIC_SESSION_EPOCH
    }
}

/// The epoch every gRPC storage connection reports. See [`Storage::connection_epoch`].
///
/// Non-zero because zero is the QUIC client's "reconnection gave up" sentinel, and nothing
/// should read that meaning into a transport that does not use it.
const GRPC_STATIC_SESSION_EPOCH: u32 = 1;

/// Revision protocol implementation over gRPC
struct GRPCRevision {
    connection: Arc<GRPCConnection>,
    client: RwLock<revision_client::RevisionService>,
    auth_url: String,
    identity: String,
    credentials: Arc<SuppliedCredentials>,
    repository: RepositoryId,
}

impl GRPCRevision {
    async fn reconnect(&self, reconnect_id: u32) -> Result<(), ProtocolError> {
        let channel = self.connection.reconnect(reconnect_id).await?;

        let mut lock = self.client.write().await;
        *lock = revision_client::RevisionService::new(
            channel,
            self.repository,
            self.connection
                .repository_authz(
                    self.auth_url.as_str(),
                    self.identity.as_str(),
                    self.repository,
                    &self.credentials,
                )
                .await,
        );

        Ok(())
    }
}

#[async_trait]
impl Revision for GRPCRevision {
    async fn branch_create(
        &self,
        branch: BranchId,
        name: &str,
        category: &str,
        creator: &str,
        stack: &[BranchPoint],
    ) -> Result<Hash, ProtocolError> {
        // boxed: the classified future is over 16 KB on Windows
        Box::pin(with_reconnect_classified(
            &self.connection,
            GrpcRpc::RevisionBranchCreate,
            || async {
                self.client
                    .read()
                    .await
                    .branch_create(branch, name, category, creator, stack)
                    .await
            },
            |reconnect_id| self.reconnect(reconnect_id),
        ))
        .await
    }

    async fn branch_delete(&self, branch: BranchId) -> Result<(), ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RevisionBranchDelete,
            || async { self.client.read().await.branch_delete(branch).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn branch_query(
        &self,
        branch: Option<BranchId>,
        name: Option<&str>,
    ) -> Result<BranchQueryResponse, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RevisionBranchQuery,
            || async { self.client.read().await.branch_query(branch, name).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn branch_push(
        &self,
        branch: BranchId,
        latest: Hash,
        force: bool,
        fast_forward_merge: bool,
    ) -> Result<BranchPushResponse, ProtocolError> {
        // boxed: the classified future is over 16 KB on Windows
        Box::pin(with_reconnect_classified(
            &self.connection,
            GrpcRpc::RevisionBranchPush,
            || async {
                self.client
                    .read()
                    .await
                    .branch_push(branch, latest, force, fast_forward_merge)
                    .await
            },
            |reconnect_id| self.reconnect(reconnect_id),
        ))
        .await
    }

    async fn branch_list(&self) -> Result<BranchListResponse, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RevisionBranchList,
            || async { self.client.read().await.branch_list().await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn revision_list(
        &self,
        signature: RevisionListStart,
    ) -> Result<RevisionListResponse, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RevisionRevisionList,
            || async {
                self.client
                    .read()
                    .await
                    .revision_list(signature.clone())
                    .await
            },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn branch_metadata_get(&self, branch: BranchId) -> Result<Hash, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RevisionBranchMetadataGet,
            || async { self.client.read().await.branch_metadata_get(branch).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn branch_metadata_set(
        &self,
        branch: BranchId,
        expected: Hash,
        new: Hash,
    ) -> Result<MetadataSetResult, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RevisionBranchMetadataSet,
            || async {
                self.client
                    .read()
                    .await
                    .branch_metadata_set(branch, expected, new)
                    .await
            },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }
}

/// Repository protocol implementation over gRPC
struct GRPCRepository {
    connection: Arc<GRPCConnection>,
    client: RwLock<repository_client::RepositoryService>,
    auth_url: String,
    identity: String,
    credentials: Arc<SuppliedCredentials>,
}

impl GRPCRepository {
    async fn reconnect(&self, reconnect_id: u32) -> Result<(), ProtocolError> {
        let channel = self.connection.reconnect(reconnect_id).await?;

        let mut lock = self.client.write().await;
        *lock = repository_client::RepositoryService::new(
            channel,
            self.connection
                .repository_authz(
                    self.auth_url.as_str(),
                    self.identity.as_str(),
                    RepositoryId::default(),
                    &self.credentials,
                )
                .await,
        );

        Ok(())
    }
}

#[async_trait]
impl Repository for GRPCRepository {
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        id: RepositoryId,
        name: &str,
        description: &str,
        default_branch_id: Context,
        default_branch_name: &str,
        creator: &str,
        created: u64,
    ) -> Result<RepositoryData, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RepositoryCreate,
            || async {
                self.client
                    .read()
                    .await
                    .create(
                        id,
                        name,
                        description,
                        default_branch_id,
                        default_branch_name,
                        creator,
                        created,
                    )
                    .await
            },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn delete(&self, id: RepositoryId) -> Result<(), ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RepositoryDelete,
            || async { self.client.read().await.delete(id).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn query(
        &self,
        id: Option<RepositoryId>,
        name: Option<&str>,
    ) -> Result<RepositoryData, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RepositoryQuery,
            || async { self.client.read().await.query(id, name).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn list(&self) -> Result<Vec<RepositoryData>, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RepositoryList,
            || async { self.client.read().await.list().await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn metadata_get(&self, id: RepositoryId) -> Result<Hash, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RepositoryMetadataGet,
            || async { self.client.read().await.metadata_get(id).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn metadata_set(
        &self,
        id: RepositoryId,
        expected: Hash,
        new: Hash,
    ) -> Result<MetadataSetResult, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::RepositoryMetadataSet,
            || async {
                self.client
                    .read()
                    .await
                    .metadata_set(id, expected, new)
                    .await
            },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }
}

/// Lock protocol implementation over gRPC
struct GRPCLock {
    connection: Arc<GRPCConnection>,
    client: RwLock<lock_client::LockService>,
    auth_url: String,
    identity: String,
    credentials: Arc<SuppliedCredentials>,
    repository: RepositoryId,
}

impl GRPCLock {
    async fn reconnect(&self, reconnect_id: u32) -> Result<(), ProtocolError> {
        let channel = self.connection.reconnect(reconnect_id).await?;

        let mut lock = self.client.write().await;
        *lock = lock_client::LockService::new(
            channel,
            self.repository,
            self.connection
                .repository_authz(
                    self.auth_url.as_str(),
                    self.identity.as_str(),
                    self.repository,
                    &self.credentials,
                )
                .await,
        );

        Ok(())
    }
}

#[async_trait]
impl Lock for GRPCLock {
    async fn lock(
        &self,
        resources: &[FencedLockResource],
        owner: Option<&str>,
    ) -> Result<Vec<AcquiredLock>, ProtocolError> {
        // boxed: the classified future is over 16 KB on Windows
        Box::pin(with_reconnect_classified(
            &self.connection,
            GrpcRpc::LockLock,
            || async { self.client.read().await.lock(resources, owner).await },
            |reconnect_id| self.reconnect(reconnect_id),
        ))
        .await
    }

    async fn query(
        &self,
        branch: Option<BranchId>,
        owner: Option<&str>,
        description: Option<&str>,
    ) -> Result<Vec<LockData>, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::LockQuery,
            || async {
                self.client
                    .read()
                    .await
                    .query(branch, owner, description)
                    .await
            },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn query_with_generation(
        &self,
        branch: Option<BranchId>,
        owner: Option<&str>,
        description: Option<&str>,
    ) -> Result<LockQueryResult, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::LockQuery,
            || async {
                self.client
                    .read()
                    .await
                    .query_with_generation(branch, owner, description)
                    .await
            },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn status(&self, resources: &[LockResource]) -> Result<Vec<LockData>, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::LockStatus,
            || async { self.client.read().await.status(resources).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn unlock(
        &self,
        resources: &[FencedLockResource],
    ) -> Result<Vec<LockResource>, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::LockUnlock,
            || async { self.client.read().await.unlock(resources).await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }

    async fn force_unlock(
        &self,
        resources: &[LockResource],
        owner: &str,
    ) -> Result<Vec<LockResource>, ProtocolError> {
        // boxed: the classified future is over 16 KB on Windows
        Box::pin(with_reconnect_classified(
            &self.connection,
            GrpcRpc::LockForceUnlock,
            || async {
                self.client
                    .read()
                    .await
                    .force_unlock(resources, owner)
                    .await
            },
            |reconnect_id| self.reconnect(reconnect_id),
        ))
        .await
    }
}

/// Environment protocol implementation over gRPC
struct GRPCEnvironment {
    connection: Arc<GRPCConnection>,
    client: RwLock<environment_client::EnvironmentService>,
}

impl GRPCEnvironment {
    async fn reconnect(&self, reconnect_id: u32) -> Result<(), ProtocolError> {
        let channel = self.connection.reconnect(reconnect_id).await?;

        let mut lock = self.client.write().await;
        *lock = environment_client::EnvironmentService::new(channel);

        Ok(())
    }
}

#[async_trait]
impl Environment for GRPCEnvironment {
    async fn get(&self) -> Result<EnvironmentConfig, ProtocolError> {
        with_reconnect_classified(
            &self.connection,
            GrpcRpc::EnvironmentGet,
            || async { self.client.read().await.get().await },
            |reconnect_id| self.reconnect(reconnect_id),
        )
        .await
    }
}

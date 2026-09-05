// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! The client half of CR-029's `DomainOperationReceiptGet` (WP-120).
//!
//! Only the receipt lookup is bound. The rest of `DomainOperationService` — prepare, stale
//! finalize, terminal-status attach, proof-namespace maintenance — is the control plane's
//! private maintenance rail, and a client binding for any of it would be an invitation to drive
//! the rail from the wrong side. A read is the whole of what a reconciler is allowed to do.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use bytes::Bytes;
use lore_base::lore_debug;
use lore_base::types::RepositoryId;
use lore_proto::lore::domain::v1::DomainOperationOutcome;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetRequest;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetResponse;
use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
use lore_proto::lore::domain::v1::domain_operation_service_client::DomainOperationServiceClient;

use super::AuthorizedService;
use super::AuthzInterceptor;
use super::Channel;
use super::GRPCAuthRef;
use super::RequestScopedCounter;
use super::grpc_retry;
use super::handle_error;
use crate::domain_receipt::DomainReceipt;
use crate::domain_receipt::DomainReceiptOutcome;
use crate::domain_receipt::DomainReceiptQuery;
use crate::domain_receipt::DomainReceiptState;
use crate::error::ProtocolError;

#[derive(Clone)]
pub struct DomainOperationService {
    client: DomainOperationServiceClient<AuthorizedService>,
    pub request_inflight: Arc<AtomicU64>,
}

impl DomainOperationService {
    pub fn new(channel: Channel, repository: RepositoryId, auth: GRPCAuthRef) -> Self {
        let client = DomainOperationServiceClient::with_interceptor(
            channel,
            AuthzInterceptor { repository, auth },
        );

        Self {
            client,
            request_inflight: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Look up the receipt for one exact attempt.
    ///
    /// The query is checked before dispatch so a structurally impossible lookup fails as a
    /// caller error rather than as an ambiguous server answer — the distinction matters, because
    /// a reconciler treats *every* inconclusive server answer as a reason to keep waiting, and
    /// waiting forever on a request that can never match is not a state anyone recovers from.
    pub async fn receipt_get(
        &self,
        query: &DomainReceiptQuery,
    ) -> Result<DomainReceipt, ProtocolError> {
        query.validate().map_err(|reason| {
            ProtocolError::internal(format!("receipt lookup rejected: {reason}"))
        })?;

        lore_debug!(
            "Looking up the domain receipt for operation {} method {}",
            query.operation_id,
            query.method
        );

        let mut retry = grpc_retry();
        let response = loop {
            // Bound to a name deliberately. `let _ = ` would drop the guard at the end of this
            // statement, leaving `request_inflight` reading zero for the whole call; the counter
            // has to live as long as the attempt it counts. It is minted per attempt rather than
            // once outside the loop so a retried lookup is one in-flight request, not two.
            let _counter = RequestScopedCounter::new(self.request_inflight.clone());

            let mut client = self.client.clone();

            match client
                .domain_operation_receipt_get(build_request(query))
                .await
            {
                Ok(response) => break response.into_inner(),
                Err(status) => handle_error(&mut retry, status).await?,
            }
        };

        decode_receipt(response)
    }
}

/// CR-029 v1 requires `authorization_id` to equal the operation id, and the server refuses a
/// request where it does not. Deriving it here rather than carrying it on the query keeps the
/// disagreement unrepresentable. A v2 that separates the two identities has to put the field
/// back on [`DomainReceiptQuery`]; this is the site that would have to change.
fn build_request(query: &DomainReceiptQuery) -> DomainOperationReceiptGetRequest {
    let operation_id = Bytes::copy_from_slice(query.operation_id.as_bytes());

    DomainOperationReceiptGetRequest {
        org_uuid: Bytes::copy_from_slice(query.org_uuid.as_bytes()),
        initiating_principal_namespace: query.initiating_principal_namespace.clone(),
        operation_id: operation_id.clone(),
        method: query.method.clone(),
        scope: query.scope.clone(),
        fingerprint_version: query.fingerprint_version,
        fingerprint: query.fingerprint.clone(),
        canonical_intent_digest: query.canonical_intent_digest.clone(),
        authorization_id: operation_id,
        authorization_revision: query.authorization_revision,
        consumed_ticket_sha256: query.consumed_ticket_sha256.clone(),
    }
}

/// Turn the wire response into the typed receipt, refusing anything self-inconsistent.
///
/// Every refusal below is a response this client cannot read as either decisive or safely
/// inconclusive, and each one is an error rather than a quiet fallback. Mapping an unreadable
/// answer onto `NotFound` would be the worst available choice: absence is a *legible* server
/// verdict that a reconciler records and keeps retrying against, so a decode failure disguised
/// as absence would look like a working lookup that simply never resolves.
fn decode_receipt(
    response: DomainOperationReceiptGetResponse,
) -> Result<DomainReceipt, ProtocolError> {
    let status = DomainOperationReceiptStatus::try_from(response.status).map_err(|_| {
        ProtocolError::internal(format!(
            "receipt lookup returned unrecognised status {}",
            response.status
        ))
    })?;

    let state = match status {
        // A status this client has no meaning for is not a state; the enum grew and this build
        // predates the growth. Refusing is the only answer that does not invent authority.
        DomainOperationReceiptStatus::Unspecified => {
            return Err(ProtocolError::internal(
                "receipt lookup returned an unspecified status",
            ));
        }
        DomainOperationReceiptStatus::Prepared => {
            let (Some(prepared_at_unix_millis), Some(hard_expires_at_unix_millis)) = (
                response.prepared_at_unix_millis,
                response.hard_expires_at_unix_millis,
            ) else {
                return Err(ProtocolError::internal(
                    "receipt lookup reported PREPARED without both of its timestamps",
                ));
            };
            DomainReceiptState::Prepared {
                prepared_at_unix_millis,
                hard_expires_at_unix_millis,
            }
        }
        DomainOperationReceiptStatus::Committed => DomainReceiptState::Committed {
            outcome: decode_outcome(&response)?,
            from_future_marker: response.from_future_marker,
        },
        DomainOperationReceiptStatus::Mismatch => DomainReceiptState::Mismatch,
        DomainOperationReceiptStatus::Expired => DomainReceiptState::Expired,
        DomainOperationReceiptStatus::ExpiredOrUnknown => DomainReceiptState::ExpiredOrUnknown,
        DomainOperationReceiptStatus::NotFound => DomainReceiptState::NotFound,
    };

    Ok(DomainReceipt {
        state,
        verification_nonce: response.verification_nonce,
        bound_fields_digest: response.bound_fields_digest,
        consumed_ticket_sha256: response.consumed_ticket_sha256,
        authorization_revision: response.authorization_revision,
    })
}

/// Read the outcome of a committed receipt.
///
/// A committed receipt without a decisive outcome is refused rather than softened into one. The
/// caller's whole reason for asking is that it does not know what happened, so an outcome it has
/// to guess at is worth less than no answer at all.
fn decode_outcome(
    response: &DomainOperationReceiptGetResponse,
) -> Result<DomainReceiptOutcome, ProtocolError> {
    let outcome = DomainOperationOutcome::try_from(response.outcome).map_err(|_| {
        ProtocolError::internal(format!(
            "committed receipt carried unrecognised outcome {}",
            response.outcome
        ))
    })?;

    match outcome {
        DomainOperationOutcome::Applied => Ok(DomainReceiptOutcome::Applied),
        // A `NOT_APPLIED` is decisive only when it is versioned, and `outcome_fields` in the
        // server always supplies a version with one. An unversioned `NOT_APPLIED` is therefore
        // not a weaker answer to be taken at face value; it is a response the contract does not
        // describe, and reading it as a verdict would resolve a durable record on evidence the
        // contract never promised. Refused for the same reason a `PREPARED` missing its
        // timestamps is.
        DomainOperationOutcome::NotApplied => {
            let Some(reason_version) = response.reason_version else {
                return Err(ProtocolError::internal(
                    "committed NOT_APPLIED receipt carried no reason version",
                ));
            };
            Ok(DomainReceiptOutcome::NotApplied {
                reason_version,
                reason: response.reason.clone(),
            })
        }
        DomainOperationOutcome::Unspecified => Err(ProtocolError::internal(
            "committed receipt carried an unspecified outcome",
        )),
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn digest() -> Bytes {
        Bytes::from_static(&[7u8; 32])
    }

    fn query() -> DomainReceiptQuery {
        DomainReceiptQuery {
            org_uuid: Uuid::now_v7(),
            initiating_principal_namespace: Bytes::from_static(b"principal-v1\0user"),
            operation_id: Uuid::now_v7(),
            method: "RevisionService.BranchCreate".to_string(),
            scope: Bytes::from_static(b"scope"),
            fingerprint_version: 1,
            fingerprint: digest(),
            canonical_intent_digest: digest(),
            authorization_revision: 3,
            consumed_ticket_sha256: digest(),
        }
    }

    fn response(status: DomainOperationReceiptStatus) -> DomainOperationReceiptGetResponse {
        DomainOperationReceiptGetResponse {
            status: status as i32,
            outcome: DomainOperationOutcome::Unspecified as i32,
            reason_version: None,
            reason: String::new(),
            from_future_marker: false,
            prepared_at_unix_millis: None,
            hard_expires_at_unix_millis: None,
            verification_nonce: digest(),
            bound_fields_digest: digest(),
            consumed_ticket_sha256: digest(),
            authorization_revision: 3,
        }
    }

    /// The equality CR-029 v1 requires is produced by the client, not asked of the caller.
    #[test]
    fn the_request_binds_authorization_id_to_the_operation_id() {
        let query = query();
        let request = build_request(&query);

        assert_eq!(request.operation_id, request.authorization_id);
        assert_eq!(request.operation_id.as_ref(), query.operation_id.as_bytes());
    }

    /// Only a committed receipt attributes anything, and only it exposes an outcome.
    #[test]
    fn committed_is_the_only_attributive_state() {
        let mut committed = response(DomainOperationReceiptStatus::Committed);
        committed.outcome = DomainOperationOutcome::Applied as i32;
        assert!(decode_receipt(committed).unwrap().state.is_attributive());

        for status in [
            DomainOperationReceiptStatus::Mismatch,
            DomainOperationReceiptStatus::Expired,
            DomainOperationReceiptStatus::ExpiredOrUnknown,
            DomainOperationReceiptStatus::NotFound,
        ] {
            let receipt = decode_receipt(response(status)).unwrap();
            assert!(
                !receipt.state.is_attributive(),
                "{status:?} must not attribute an outcome"
            );
        }
    }

    /// A committed receipt whose outcome is missing is refused, not read as either verdict.
    #[test]
    fn a_committed_receipt_without_an_outcome_is_refused() {
        let error = decode_receipt(response(DomainOperationReceiptStatus::Committed))
            .expect_err("an unspecified outcome must not decode");

        assert!(
            format!("{error}").contains("unspecified outcome"),
            "expected the unspecified-outcome refusal, got: {error}"
        );
    }

    /// A `NOT_APPLIED` keeps its versioned reason as data for the caller to branch on.
    #[test]
    fn a_not_applied_receipt_keeps_its_versioned_reason() {
        let mut committed = response(DomainOperationReceiptStatus::Committed);
        committed.outcome = DomainOperationOutcome::NotApplied as i32;
        committed.reason_version = Some(2);
        committed.reason = "BRANCH_PROTECTED".to_string();
        committed.from_future_marker = true;

        let receipt = decode_receipt(committed).unwrap();

        assert_eq!(
            receipt.state,
            DomainReceiptState::Committed {
                outcome: DomainReceiptOutcome::NotApplied {
                    reason_version: 2,
                    reason: "BRANCH_PROTECTED".to_string(),
                },
                from_future_marker: true,
            }
        );
    }

    /// WP-120 makes a `NOT_APPLIED` decisive only when it is versioned, and the server always
    /// sends a version with one. An unversioned one is refused rather than acted on.
    #[test]
    fn a_not_applied_receipt_without_a_reason_version_is_refused() {
        let mut committed = response(DomainOperationReceiptStatus::Committed);
        committed.outcome = DomainOperationOutcome::NotApplied as i32;
        committed.reason = "BRANCH_PROTECTED".to_string();

        let error = decode_receipt(committed).expect_err("an unversioned NOT_APPLIED must decode");

        assert!(
            format!("{error}").contains("no reason version"),
            "expected the missing-reason-version refusal, got: {error}"
        );
    }

    /// The safety property, stated as a test rather than left to the shape of the types: an
    /// outcome riding along on a status that does not attribute anything is dropped on the
    /// floor. A reconciler cannot see it, so it cannot resolve a record on it.
    #[test]
    fn an_outcome_on_a_non_committed_status_never_surfaces() {
        for status in [
            DomainOperationReceiptStatus::Mismatch,
            DomainOperationReceiptStatus::Expired,
            DomainOperationReceiptStatus::ExpiredOrUnknown,
            DomainOperationReceiptStatus::NotFound,
        ] {
            let mut smuggled = response(status);
            smuggled.outcome = DomainOperationOutcome::Applied as i32;
            smuggled.reason_version = Some(1);
            smuggled.reason = "must not surface".to_string();
            smuggled.from_future_marker = true;

            let receipt = decode_receipt(smuggled)
                .unwrap_or_else(|e| panic!("{status:?} must still decode: {e}"));

            assert!(
                !receipt.state.is_attributive(),
                "{status:?} must not attribute an outcome"
            );
            assert!(
                !matches!(receipt.state, DomainReceiptState::Committed { .. }),
                "{status:?} must not decode as committed"
            );
        }
    }

    /// A prepare missing either timestamp is refused rather than back-filled with a default.
    #[test]
    fn a_prepared_receipt_needs_both_timestamps() {
        let mut prepared = response(DomainOperationReceiptStatus::Prepared);
        prepared.prepared_at_unix_millis = Some(10);

        assert!(decode_receipt(prepared.clone()).is_err());

        prepared.hard_expires_at_unix_millis = Some(20);
        assert_eq!(
            decode_receipt(prepared).unwrap().state,
            DomainReceiptState::Prepared {
                prepared_at_unix_millis: 10,
                hard_expires_at_unix_millis: 20,
            }
        );
    }

    /// A status outside this build's vocabulary is refused, never softened into absence.
    #[test]
    fn an_unreadable_status_is_refused_rather_than_read_as_absence() {
        let mut unknown = response(DomainOperationReceiptStatus::NotFound);
        unknown.status = 4242;

        assert!(decode_receipt(unknown).is_err());
        assert!(decode_receipt(response(DomainOperationReceiptStatus::Unspecified)).is_err());
    }

    /// The structural checks run before anything reaches the wire.
    #[test]
    fn a_structurally_impossible_query_is_rejected() {
        let mut short_digest = query();
        short_digest.fingerprint = Bytes::from_static(&[1u8; 16]);
        assert!(short_digest.validate().is_err());

        let mut zero_version = query();
        zero_version.fingerprint_version = 0;
        assert!(zero_version.validate().is_err());

        let mut not_v7 = query();
        not_v7.operation_id = Uuid::from_bytes([9u8; 16]);
        assert!(not_v7.validate().is_err());

        assert!(query().validate().is_ok());
    }
}

/// Live-wire coverage against an in-process `tonic` double: does the auth interceptor actually
/// put the caller's bearer token and repository id on the wire, does every receipt status decode
/// through a real protobuf round trip (not just a hand-built `decode_receipt` call), does a
/// human-JWT-shaped `PermissionDenied` (the real server's answer for a non-service-account
/// caller against this control-plane-only RPC, per `lore-server`'s `authenticated_service`)
/// surface as a typed error rather than a panic, and does an invalid query short-circuit before
/// ever reaching the double. Follows `storage_client.rs`'s test-module convention: a real
/// `tonic::transport::Server` on an ephemeral port, a real `Channel`, no mock framework.
#[cfg(test)]
mod live_tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use lore_proto::lore::domain::v1::DomainOperationClockGetRequest;
    use lore_proto::lore::domain::v1::DomainOperationClockGetResponse;
    use lore_proto::lore::domain::v1::DomainOperationPrepareRequest;
    use lore_proto::lore::domain::v1::DomainOperationPrepareResponse;
    use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeReceiptV1;
    use lore_proto::lore::domain::v1::DomainOperationProofNamespaceMaterializeRequestV1;
    use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireAckV1;
    use lore_proto::lore::domain::v1::DomainOperationProofNamespaceRetireRequestV1;
    use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachRequest;
    use lore_proto::lore::domain::v1::DomainOperationTerminalStatusAttachmentAckV1;
    use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeRequest;
    use lore_proto::lore::domain::v1::DomainOperationVerifiedStaleFinalizeResponse;
    use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationService as DomainOperationServiceTrait;
    use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationServiceServer;
    use tonic::Request;
    use tonic::Response;
    use tonic::Status;
    use uuid::Uuid;

    use super::*;

    fn digest(fill: u8) -> Bytes {
        Bytes::from(vec![fill; 32])
    }

    fn query() -> DomainReceiptQuery {
        DomainReceiptQuery {
            org_uuid: Uuid::now_v7(),
            initiating_principal_namespace: Bytes::from_static(b"principal-v1\0user"),
            operation_id: Uuid::now_v7(),
            method: "RevisionService.BranchCreate".to_string(),
            scope: Bytes::from_static(b"scope"),
            fingerprint_version: 1,
            fingerprint: digest(0xAA),
            canonical_intent_digest: digest(0xBB),
            authorization_revision: 3,
            consumed_ticket_sha256: digest(0xCC),
        }
    }

    fn wire_response(status: DomainOperationReceiptStatus) -> DomainOperationReceiptGetResponse {
        DomainOperationReceiptGetResponse {
            status: status as i32,
            outcome: DomainOperationOutcome::Unspecified as i32,
            reason_version: None,
            reason: String::new(),
            from_future_marker: false,
            prepared_at_unix_millis: None,
            hard_expires_at_unix_millis: None,
            verification_nonce: digest(1),
            bound_fields_digest: digest(2),
            consumed_ticket_sha256: digest(3),
            authorization_revision: 3,
        }
    }

    /// What the double answers a `domain_operation_receipt_get` call with, and what it can be
    /// told to do instead for the failure-shaped tests.
    #[derive(Clone)]
    enum ReceiptGetBehavior {
        Respond(DomainOperationReceiptGetResponse),
        Fail(tonic::Code, &'static str),
    }

    /// Implements only `domain_operation_receipt_get`; every other `DomainOperationService`
    /// method is unreachable from this client binding by design (see this module's own doc
    /// comment) and returns `Unimplemented` if a regression ever calls one.
    struct FakeDomainOperationServer {
        behavior: ReceiptGetBehavior,
        calls: Arc<AtomicUsize>,
        seen_authorization: Arc<Mutex<Option<String>>>,
        seen_repository_id: Arc<Mutex<Option<Vec<u8>>>>,
        seen_authorization_id_equals_operation_id: Arc<Mutex<Option<bool>>>,
    }

    #[tonic::async_trait]
    impl DomainOperationServiceTrait for FakeDomainOperationServer {
        async fn domain_operation_clock_get(
            &self,
            _request: Request<DomainOperationClockGetRequest>,
        ) -> Result<Response<DomainOperationClockGetResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn domain_operation_prepare(
            &self,
            _request: Request<DomainOperationPrepareRequest>,
        ) -> Result<Response<DomainOperationPrepareResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn domain_operation_receipt_get(
            &self,
            request: Request<DomainOperationReceiptGetRequest>,
        ) -> Result<Response<DomainOperationReceiptGetResponse>, Status> {
            self.calls.fetch_add(1, Ordering::SeqCst);

            let authorization = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            *self.seen_authorization.lock().unwrap() = authorization;

            let repository_id = request
                .metadata()
                .get_bin(super::super::REPOSITORY_ID_KEY)
                .and_then(|value| value.to_bytes().ok())
                .map(|bytes| bytes.to_vec());
            *self.seen_repository_id.lock().unwrap() = repository_id;

            let body = request.get_ref();
            *self
                .seen_authorization_id_equals_operation_id
                .lock()
                .unwrap() = Some(body.authorization_id == body.operation_id);

            match self.behavior.clone() {
                ReceiptGetBehavior::Respond(response) => Ok(Response::new(response)),
                ReceiptGetBehavior::Fail(code, message) => Err(Status::new(code, message)),
            }
        }

        async fn domain_operation_verified_stale_finalize(
            &self,
            _request: Request<DomainOperationVerifiedStaleFinalizeRequest>,
        ) -> Result<Response<DomainOperationVerifiedStaleFinalizeResponse>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn domain_operation_terminal_status_attach(
            &self,
            _request: Request<DomainOperationTerminalStatusAttachRequest>,
        ) -> Result<Response<DomainOperationTerminalStatusAttachmentAckV1>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn domain_operation_proof_namespace_materialize(
            &self,
            _request: Request<DomainOperationProofNamespaceMaterializeRequestV1>,
        ) -> Result<Response<DomainOperationProofNamespaceMaterializeReceiptV1>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }

        async fn domain_operation_proof_namespace_retire(
            &self,
            _request: Request<DomainOperationProofNamespaceRetireRequestV1>,
        ) -> Result<Response<DomainOperationProofNamespaceRetireAckV1>, Status> {
            Err(Status::unimplemented("not used by this test"))
        }
    }

    struct TestDomainOperations {
        client: DomainOperationService,
        calls: Arc<AtomicUsize>,
        seen_authorization: Arc<Mutex<Option<String>>>,
        seen_repository_id: Arc<Mutex<Option<Vec<u8>>>>,
        seen_authorization_id_equals_operation_id: Arc<Mutex<Option<bool>>>,
    }

    /// Stand up a real `DomainOperationService` gRPC server on an ephemeral port and a client
    /// bound to it through the same `AuthzInterceptor` production traffic goes through -- no
    /// mock, no shortcut around the interceptor.
    async fn start_test_domain_operations(
        behavior: ReceiptGetBehavior,
        auth_token: &str,
        repository: RepositoryId,
    ) -> TestDomainOperations {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen_authorization = Arc::new(Mutex::new(None));
        let seen_repository_id = Arc::new(Mutex::new(None));
        let seen_authorization_id_equals_operation_id = Arc::new(Mutex::new(None));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let server = FakeDomainOperationServer {
            behavior,
            calls: calls.clone(),
            seen_authorization: seen_authorization.clone(),
            seen_repository_id: seen_repository_id.clone(),
            seen_authorization_id_equals_operation_id: seen_authorization_id_equals_operation_id
                .clone(),
        };

        #[allow(clippy::disallowed_methods)] // Test-local server task.
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(DomainOperationServiceServer::new(server))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .expect("connect to test server");
        let channel = tower::ServiceBuilder::new()
            .layer(super::super::RequestLoggerLayer {})
            .service(channel);

        let auth: GRPCAuthRef = Arc::new(parking_lot::RwLock::new(super::super::GRPCAuth {
            authorization_token: auth_token.to_string(),
            ..Default::default()
        }));

        TestDomainOperations {
            client: DomainOperationService::new(channel, repository, auth),
            calls,
            seen_authorization,
            seen_repository_id,
            seen_authorization_id_equals_operation_id,
        }
    }

    /// The interceptor that wraps this client's `DomainOperationServiceClient` is the same
    /// `AuthzInterceptor` every other client in this module uses -- this proves it actually runs
    /// for `DomainOperationReceiptGet`, not just that it compiles against the type.
    #[tokio::test]
    async fn the_bearer_token_and_repository_id_reach_the_server() {
        let repository = RepositoryId::from([0x42u8; 16]);
        let harness = start_test_domain_operations(
            ReceiptGetBehavior::Respond(wire_response(DomainOperationReceiptStatus::NotFound)),
            "test-lore-jwt",
            repository,
        )
        .await;

        let result = harness.client.receipt_get(&query()).await;
        assert!(result.is_ok(), "expected a decoded receipt: {result:?}");

        assert_eq!(
            harness.seen_authorization.lock().unwrap().as_deref(),
            Some("Bearer test-lore-jwt"),
            "AuthzInterceptor must attach the caller's bearer token to the wire request"
        );
        assert_eq!(
            harness.seen_repository_id.lock().unwrap().as_deref(),
            Some(repository.data().as_slice()),
            "AuthzInterceptor must attach the repository id to the wire request"
        );
    }

    /// `the_request_binds_authorization_id_to_the_operation_id` (in this file's own `mod tests`)
    /// proves `build_request` sets the two fields equal. This is the companion the lane asked
    /// for: proving that equality survives an actual protobuf encode/decode round trip over a
    /// real connection, not just the in-memory struct `build_request` returns.
    #[tokio::test]
    async fn the_wire_request_binds_authorization_id_to_the_operation_id() {
        let harness = start_test_domain_operations(
            ReceiptGetBehavior::Respond(wire_response(DomainOperationReceiptStatus::NotFound)),
            "test-lore-jwt",
            RepositoryId::from([0x01u8; 16]),
        )
        .await;

        harness
            .client
            .receipt_get(&query())
            .await
            .expect("expected a decoded receipt");

        assert_eq!(
            *harness
                .seen_authorization_id_equals_operation_id
                .lock()
                .unwrap(),
            Some(true),
            "authorization_id must equal operation_id as received by the server, not just as \
             built client-side"
        );
    }

    /// Every status this client's vocabulary covers, decoded through a REAL protobuf
    /// serialize/deserialize round trip rather than a hand-built response passed directly to
    /// `decode_receipt` (which the file's own `mod tests` already covers). `NotFound` is the
    /// pinned "absent maps to absent, not error" case: the call must return `Ok`, never `Err`.
    #[tokio::test]
    async fn every_receipt_status_decodes_through_a_real_wire_round_trip() {
        let cases: Vec<(DomainOperationReceiptStatus, DomainReceiptState)> = vec![
            (
                DomainOperationReceiptStatus::Mismatch,
                DomainReceiptState::Mismatch,
            ),
            (
                DomainOperationReceiptStatus::Expired,
                DomainReceiptState::Expired,
            ),
            (
                DomainOperationReceiptStatus::ExpiredOrUnknown,
                DomainReceiptState::ExpiredOrUnknown,
            ),
            (
                DomainOperationReceiptStatus::NotFound,
                DomainReceiptState::NotFound,
            ),
        ];

        for (wire_status, expected_state) in cases {
            let harness = start_test_domain_operations(
                ReceiptGetBehavior::Respond(wire_response(wire_status)),
                "test-lore-jwt",
                RepositoryId::from([0x01u8; 16]),
            )
            .await;

            let receipt = harness
                .client
                .receipt_get(&query())
                .await
                .unwrap_or_else(|err| panic!("{wire_status:?} must decode, got {err:?}"));

            assert_eq!(
                receipt.state, expected_state,
                "wire status {wire_status:?} must decode to {expected_state:?}"
            );
            assert!(
                !receipt.state.is_attributive(),
                "{expected_state:?} must not be attributive"
            );
        }

        let mut prepared = wire_response(DomainOperationReceiptStatus::Prepared);
        prepared.prepared_at_unix_millis = Some(10);
        prepared.hard_expires_at_unix_millis = Some(20);
        let harness = start_test_domain_operations(
            ReceiptGetBehavior::Respond(prepared),
            "test-lore-jwt",
            RepositoryId::from([0x01u8; 16]),
        )
        .await;
        let receipt = harness.client.receipt_get(&query()).await.unwrap();
        assert_eq!(
            receipt.state,
            DomainReceiptState::Prepared {
                prepared_at_unix_millis: 10,
                hard_expires_at_unix_millis: 20,
            }
        );

        let mut committed = wire_response(DomainOperationReceiptStatus::Committed);
        committed.outcome = DomainOperationOutcome::Applied as i32;
        let harness = start_test_domain_operations(
            ReceiptGetBehavior::Respond(committed),
            "test-lore-jwt",
            RepositoryId::from([0x01u8; 16]),
        )
        .await;
        let receipt = harness.client.receipt_get(&query()).await.unwrap();
        assert_eq!(
            receipt.state,
            DomainReceiptState::Committed {
                outcome: DomainReceiptOutcome::Applied,
                from_future_marker: false,
            }
        );
        assert!(receipt.state.is_attributive());
    }

    /// The real server rejects a caller whose verified JWT is not the control-plane service
    /// account (`lore-server/src/grpc/domain/v1/service.rs`'s `authenticated_service`), which is
    /// exactly what a human-principal desktop caller is against this RPC today. That refusal
    /// must surface as this client's typed `NotAuthorized`, never as a panic or a silently
    /// swallowed error.
    #[tokio::test]
    async fn a_permission_denied_status_surfaces_as_a_typed_not_authorized_error() {
        let harness = start_test_domain_operations(
            ReceiptGetBehavior::Fail(
                tonic::Code::PermissionDenied,
                "Repository operation rail requires a verified service account",
            ),
            "human-principal-jwt",
            RepositoryId::from([0x01u8; 16]),
        )
        .await;

        let error = harness
            .client
            .receipt_get(&query())
            .await
            .expect_err("a PermissionDenied status must not decode as a successful receipt");

        assert!(
            error.is_not_authorized(),
            "PermissionDenied must map to ProtocolError::NotAuthorized, got {error:?}"
        );
    }

    /// A real connection failure (the code an h2 stream reset produces) must surface as this
    /// client's typed `Disconnected`, not a panic and not a successful decode.
    #[tokio::test]
    async fn a_connection_failure_status_surfaces_as_a_typed_disconnected_error() {
        let harness = start_test_domain_operations(
            ReceiptGetBehavior::Fail(tonic::Code::Unavailable, "connection reset"),
            "test-lore-jwt",
            RepositoryId::from([0x01u8; 16]),
        )
        .await;

        let error = harness
            .client
            .receipt_get(&query())
            .await
            .expect_err("an Unavailable status must not decode as a successful receipt");

        assert!(
            error.is_disconnected(),
            "Unavailable must map to ProtocolError::Disconnected, got {error:?}"
        );
    }

    /// `receipt_get` validates before it dispatches. A structurally impossible query must never
    /// reach the wire at all -- proven here by a double that would happily answer but never sees
    /// a call.
    #[tokio::test]
    async fn a_structurally_invalid_query_never_reaches_the_server() {
        let harness = start_test_domain_operations(
            ReceiptGetBehavior::Respond(wire_response(DomainOperationReceiptStatus::NotFound)),
            "test-lore-jwt",
            RepositoryId::from([0x01u8; 16]),
        )
        .await;

        let mut invalid = query();
        invalid.fingerprint_version = 0;

        let error = harness
            .client
            .receipt_get(&invalid)
            .await
            .expect_err("a structurally invalid query must be rejected client-side");

        assert!(
            format!("{error}").contains("fingerprint_version"),
            "expected the validation failure to name the offending field, got: {error}"
        );
        assert_eq!(
            harness.calls.load(Ordering::SeqCst),
            0,
            "an invalid query must never reach the server"
        );
    }
}

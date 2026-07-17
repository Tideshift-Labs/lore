// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use lore_transport::quic::QuicOpCode;
use lore_transport::quic::QuicServiceError;
use lore_transport::quic::UnknownCommand;
use lore_transport::quic::command_header::COMMAND_HEADER_SIZE_V4;
use lore_transport::quic::command_header::CommandHeader;
use lore_transport::quic::storage_service::Command;
use lore_transport::quic::storage_service::MAX_CHUNK_SIZE;
use lore_transport::quic::storage_service::command_name;
use tracing::Span;
use tracing::debug;

use crate::auth::jwt::JwtVerifier;
use crate::protocol::attribute_map::AttributeMap;
use crate::protocol::attribute_map::ConnectionId;
use crate::protocol::storage::authorize::AuthorizeAction;
use crate::protocol::storage::authorize::parse_authorize;
use crate::protocol::storage::copy::handle_copy;
use crate::protocol::storage::get::handle_get;
use crate::protocol::storage::messages::MessageHandleError;
use crate::protocol::storage::messages::MessageParseError;
use crate::protocol::storage::messages::Response;
use crate::protocol::storage::mutable_cas::handle_mutable_cas;
use crate::protocol::storage::mutable_load::handle_mutable_load;
use crate::protocol::storage::mutable_store_handler::handle_mutable_store;
use crate::protocol::storage::put::handle_put;
use crate::protocol::storage::query::handle_query;
use crate::protocol::storage::session::SessionError;
use crate::protocol::storage::session::SessionMap;
use crate::protocol::storage::verify::handle_verify;
use crate::quic::NO_CONNECTION_ID;
use crate::quic::NO_CORRELATION_ID;
use crate::quic::NO_REPOSITORY_ID;
use crate::quic::NO_USER_ID;
use crate::quic::ProtocolErrorInfo;
use crate::quic::QuicErrorStatus;
use crate::quic::QuicService;
use crate::quic::storage_service::build_storage_protocol_request_span;
use crate::quic::storage_service::is_internal_error;
use crate::quic::storage_service::message_handle_error_to_label;
use crate::quic::storage_service::parse_message_for_opcode_v4;
use crate::telemetry::StorageProtocol;

const RESERVED_OPCODE_PING: QuicOpCode = 4;
const RESERVED_OPCODE_CORRELATE: QuicOpCode = 5;

#[derive(Debug)]
pub enum ParsedStorageRequestV4 {
    AuthorizeStart {
        repository: lore_revision::lore::RepositoryId,
        correlation_id: String,
        auth_token: Vec<u8>,
    },
    AuthorizeStop {
        session_id: u32,
    },
    StorageCommand {
        session_id: u32,
        opcode: QuicOpCode,
        payload: Bytes,
    },
}

fn quic_error_v4(error: &MessageHandleError) -> QuicServiceError {
    match error {
        MessageHandleError::AuthorizationFailure(_) | MessageHandleError::MissingToken => {
            QuicServiceError::NotAuthorized
        }
        MessageHandleError::FragmentNotFound | MessageHandleError::MutableDataNotFound(_) => {
            QuicServiceError::NotFound
        }
        MessageHandleError::SlowDown | MessageHandleError::SessionLimitReached => {
            QuicServiceError::SlowDown
        }
        MessageHandleError::Oversized => QuicServiceError::Oversized,
        _ => QuicServiceError::Failed,
    }
}

pub struct StorageServiceV4 {
    jwt_verifier: Arc<Option<JwtVerifier>>,
    immutable_store: Arc<dyn ImmutableStore>,
    local_store: Arc<dyn ImmutableStore>,
    mutable_store: Arc<dyn MutableStore>,
    session_map: Arc<SessionMap>,
    enforce_write_permission: bool,
}

impl StorageServiceV4 {
    pub fn new(
        jwt_verifier: Arc<Option<JwtVerifier>>,
        immutable_store: Arc<dyn ImmutableStore>,
        local_store: Arc<dyn ImmutableStore>,
        mutable_store: Arc<dyn MutableStore>,
        enforce_write_permission: bool,
    ) -> Self {
        Self {
            jwt_verifier,
            immutable_store,
            local_store,
            mutable_store,
            session_map: Arc::new(SessionMap::default()),
            enforce_write_permission,
        }
    }

    /// Enforce the write-path permission for a storage command. Mirrors the
    /// gRPC-side `require_permission` semantics: a no-op when auth is off (no
    /// verifier) or enforcement is disabled; otherwise the session must have
    /// snapshotted `write` for its repository at `AuthorizeStart`.
    fn require_write(
        &self,
        permissions: &[String],
        operation: &'static str,
    ) -> Result<(), MessageHandleError> {
        if crate::auth::jwt::write_permission_granted(
            self.jwt_verifier.is_some(),
            self.enforce_write_permission,
            permissions,
        ) {
            return Ok(());
        }
        Err(MessageHandleError::AuthorizationFailure(format!(
            "write permission required for {operation}"
        )))
    }
}

#[async_trait]
impl QuicService for StorageServiceV4 {
    type ParsedRequestType = ParsedStorageRequestV4;
    type RequestParseErrorType = MessageParseError;
    type RequestHandlerError = MessageHandleError;

    fn get_service_name_label(&self) -> &'static str {
        StorageProtocol::StorageV4.as_str()
    }

    fn parse_request_bytes(
        &self,
        header: &CommandHeader,
        bytes: Bytes,
    ) -> Result<Self::ParsedRequestType, Self::RequestParseErrorType> {
        let opcode = header.cmd;
        let session_id = header.session_id;

        if opcode == RESERVED_OPCODE_PING || opcode == RESERVED_OPCODE_CORRELATE {
            return Err(MessageParseError::UnknownOpcode(opcode));
        }

        if opcode == Command::Authorize as u8 {
            let action = parse_authorize(session_id, bytes)?;
            return match action {
                AuthorizeAction::Start(start) => Ok(ParsedStorageRequestV4::AuthorizeStart {
                    repository: start.repository,
                    correlation_id: start.correlation_id,
                    auth_token: start.auth_token,
                }),
                AuthorizeAction::Stop(stop) => Ok(ParsedStorageRequestV4::AuthorizeStop {
                    session_id: stop.session_id,
                }),
            };
        }

        // Validate this is a known storage opcode (but don't parse yet — we need session context)
        let _command: Command = opcode
            .try_into()
            .map_err(|_err| MessageParseError::UnknownOpcode(opcode))?;

        Ok(ParsedStorageRequestV4::StorageCommand {
            session_id,
            opcode,
            payload: bytes,
        })
    }

    async fn run_request_handler(
        &self,
        _context: Arc<AttributeMap>,
        request: Self::ParsedRequestType,
    ) -> Result<Vec<Bytes>, Self::RequestHandlerError> {
        match request {
            ParsedStorageRequestV4::AuthorizeStart {
                repository,
                correlation_id,
                auth_token,
            } => {
                let mut user_id = String::new();
                let mut permissions: Vec<String> = Vec::new();

                if let Some(jwt_verifier) = self.jwt_verifier.as_ref() {
                    let token_str = String::from_utf8(auth_token).map_err(|err| {
                        MessageHandleError::AuthorizationFailure(format!(
                            "invalid token encoding: {err}"
                        ))
                    })?;

                    if token_str.is_empty() {
                        return Err(MessageHandleError::MissingToken);
                    }

                    let authorization = jwt_verifier
                        .verify_token(&token_str)
                        .await
                        .map_err(|err| MessageHandleError::AuthorizationFailure(err.to_string()))?;

                    crate::auth::jwt::verify_authorization(&authorization, repository)
                        .map_err(|err| MessageHandleError::AuthorizationFailure(err.to_string()))?;

                    permissions =
                        crate::auth::jwt::matching_permissions(&authorization, repository);
                    user_id = crate::util::get_user_id_from_token(Some(authorization));
                }

                let session_map = self.session_map.clone();
                match session_map.start(repository, correlation_id, user_id, permissions) {
                    Ok((session_id, correlation_id)) => {
                        debug!(
                            session_id,
                            repository = %repository,
                            correlation_id,
                            "Authorized session"
                        );
                        let response_data = vec![Bytes::copy_from_slice(&session_id.to_le_bytes())];
                        Ok(response_data)
                    }
                    Err(SessionError::LimitReached) => Err(MessageHandleError::SessionLimitReached),
                    Err(SessionError::CounterExhausted | SessionError::NotFound) => {
                        Err(MessageHandleError::InternalError)
                    }
                }
            }
            ParsedStorageRequestV4::AuthorizeStop { session_id } => {
                let session_map = self.session_map.clone();
                match session_map.stop(session_id) {
                    Ok(()) => {
                        debug!(session_id, "Session stopped");
                        Ok(vec![])
                    }
                    Err(SessionError::NotFound) => Err(MessageHandleError::NotConnected),
                    Err(_) => Err(MessageHandleError::InternalError),
                }
            }
            ParsedStorageRequestV4::StorageCommand {
                session_id,
                opcode,
                payload,
            } => {
                let session_map = self.session_map.clone();
                let session = session_map
                    .get(session_id)
                    .ok_or(MessageHandleError::NotConnected)?;

                let repository = session.repository;
                let correlation_id = session.correlation_id.clone();
                let user_id = session.user_id.clone();
                let permissions = session.permissions.clone();
                drop(session);

                // Parse the storage command payload using v4-aware parsers — Copy carries an
                // extra `target_context` field on the wire that the legacy parser cannot decode.
                let parsed = parse_message_for_opcode_v4(opcode, payload).map_err(|err| {
                    tracing::warn!("Failed to parse v4 storage command: {err}");
                    MessageHandleError::InternalError
                })?;

                // Write-path permission gate (read ≠ write). The session has no
                // per-request token; enforcement runs against the permissions
                // snapshotted at AuthorizeStart. Verify counts as a write only
                // when healing (it rewrites stored fragments). The match is
                // EXHAUSTIVE on purpose: a new `ParsedStorageRequest` variant
                // (e.g. from an upstream merge) must fail to compile here so its
                // write-vs-read classification is a deliberate decision, never a
                // silent fall-through to "ungated".
                use crate::quic::storage_service::ParsedStorageRequest as Req;
                match &parsed {
                    Req::Put(_) => self.require_write(&permissions, "Put")?,
                    Req::Copy(_) => self.require_write(&permissions, "Copy")?,
                    Req::MutableStoreOp(_) => self.require_write(&permissions, "MutableStore")?,
                    Req::MutableCas(_) => self.require_write(&permissions, "MutableCas")?,
                    Req::Verify(verify) if verify.heal != 0 => {
                        self.require_write(&permissions, "Verify(heal)")?
                    }
                    // Reads (and Verify without heal) are ungated.
                    Req::Verify(_)
                    | Req::Get(_)
                    | Req::GetMetadata(_)
                    | Req::Query(_)
                    | Req::MutableLoad(_)
                    | Req::Connect(_)
                    | Req::Correlate(_) => {}
                }

                // Dispatch to standalone handler functions with explicit session context
                let response = match parsed {
                    crate::quic::storage_service::ParsedStorageRequest::Get(get) => {
                        handle_get(
                            get.address,
                            repository,
                            correlation_id,
                            user_id,
                            self.immutable_store.clone(),
                        )
                        .await
                    }
                    crate::quic::storage_service::ParsedStorageRequest::GetMetadata(get) => {
                        crate::protocol::storage::get::handle_get_metadata(
                            get.address,
                            repository,
                            correlation_id,
                            user_id,
                            self.immutable_store.clone(),
                        )
                        .await
                    }
                    crate::quic::storage_service::ParsedStorageRequest::Put(put) => {
                        handle_put(
                            &put,
                            repository,
                            correlation_id,
                            user_id,
                            self.immutable_store.clone(),
                        )
                        .await
                    }
                    crate::quic::storage_service::ParsedStorageRequest::Query(_query) => {
                        // Query uses the raw bytes, not the parsed struct.
                        // Re-parse is needed because parse_message_for_opcode_v4 consumed the bytes.
                        // However, the Query struct stores the bytes internally.
                        handle_query(&_query.address, repository, self.immutable_store.clone())
                            .await
                    }
                    crate::quic::storage_service::ParsedStorageRequest::Verify(verify) => {
                        handle_verify(
                            verify.address,
                            verify.heal,
                            repository,
                            correlation_id,
                            user_id,
                            self.local_store.clone(),
                        )
                        .await
                    }
                    crate::quic::storage_service::ParsedStorageRequest::Copy(copy) => {
                        handle_copy(
                            copy.source_repository,
                            copy.source_address,
                            repository,
                            copy.target_context,
                            correlation_id,
                            user_id,
                            Some(&session_map),
                            self.immutable_store.clone(),
                        )
                        .await
                    }
                    crate::quic::storage_service::ParsedStorageRequest::MutableLoad(load) => {
                        handle_mutable_load(
                            load.key,
                            load.key_type,
                            repository,
                            correlation_id,
                            user_id,
                            self.mutable_store.clone(),
                        )
                        .await
                    }
                    crate::quic::storage_service::ParsedStorageRequest::MutableStoreOp(store) => {
                        handle_mutable_store(
                            store.key,
                            store.value,
                            store.key_type,
                            repository,
                            correlation_id,
                            user_id,
                            self.mutable_store.clone(),
                        )
                        .await
                    }
                    crate::quic::storage_service::ParsedStorageRequest::MutableCas(cas) => {
                        handle_mutable_cas(
                            cas.key,
                            cas.expected,
                            cas.value,
                            cas.key_type,
                            repository,
                            correlation_id,
                            user_id,
                            self.mutable_store.clone(),
                        )
                        .await
                    }
                    // Connect and Correlate are v2-only, handled as reserved opcodes above
                    crate::quic::storage_service::ParsedStorageRequest::Connect(_)
                    | crate::quic::storage_service::ParsedStorageRequest::Correlate(_) => {
                        Err(MessageHandleError::NotImplemented)
                    }
                }?;

                Ok(response.data())
            }
        }
    }

    fn command_to_metrics_label(&self, opcode: QuicOpCode) -> &'static str {
        if opcode == RESERVED_OPCODE_PING || opcode == RESERVED_OPCODE_CORRELATE {
            return "reserved";
        }
        if opcode == Command::Authorize as u8 {
            return "authorize";
        }
        let command: Result<Command, UnknownCommand> = opcode.try_into();
        match command {
            Ok(command) => command_name(&command),
            Err(_) => "unknown",
        }
    }

    fn transform_protocol_error(&self, error: &Self::RequestHandlerError) -> ProtocolErrorInfo {
        let service_error = quic_error_v4(error);
        let is_appropriate_for_logging = !matches!(
            service_error,
            QuicServiceError::SlowDown | QuicServiceError::NotFound
        );

        ProtocolErrorInfo {
            response_error_code: service_error as QuicErrorStatus,
            message_handle_label: message_handle_error_to_label(error),
            is_internal_error: is_internal_error(error),
            is_appropriate_for_logging,
        }
    }

    fn max_chunk_size(&self) -> usize {
        MAX_CHUNK_SIZE
    }

    fn header_size(&self) -> usize {
        COMMAND_HEADER_SIZE_V4
    }

    fn build_request_span(
        &self,
        header: &CommandHeader,
        _message: &Self::ParsedRequestType,
        context: &Arc<AttributeMap>,
    ) -> Span {
        let connection_id = context
            .get::<ConnectionId>()
            .map_or_else(|| NO_CONNECTION_ID.to_string(), |id| id.0.to_string());

        let session = if header.session_id != 0 {
            self.session_map.get(header.session_id)
        } else {
            None
        };

        let (repository_id, correlation_id, user_id) = match session {
            Some(session) => {
                let repository_id = session.repository.to_string();
                let repository_id = if repository_id.is_empty() {
                    NO_REPOSITORY_ID.to_string()
                } else {
                    repository_id
                };
                let correlation_id = if session.correlation_id.is_empty() {
                    NO_CORRELATION_ID.to_string()
                } else {
                    session.correlation_id.clone()
                };
                let user_id = if session.user_id.is_empty() {
                    NO_USER_ID.to_string()
                } else {
                    session.user_id.clone()
                };
                (repository_id, correlation_id, user_id)
            }
            None => (
                NO_REPOSITORY_ID.to_string(),
                NO_CORRELATION_ID.to_string(),
                NO_USER_ID.to_string(),
            ),
        };

        build_storage_protocol_request_span(
            header.cmd,
            StorageProtocol::StorageV4,
            &connection_id,
            &repository_id,
            &correlation_id,
            &user_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use lore_base::types::KeyType;
    use lore_transport::quic::QuicServiceError;
    use rand::random;
    use zerocopy::IntoBytes;

    use super::*;
    use crate::auth::jwk::JWKService;
    use crate::auth::jwk::JWKServiceError;
    use crate::protocol::storage::session::MAX_CONCURRENT_SESSIONS;
    use crate::quic::QuicService;
    use crate::store::test_store_create;

    /// A `JWKService` that must never be called — used to build a `JwtVerifier`
    /// for tests that seed a session's permissions directly (bypassing
    /// `AuthorizeStart`, and with it `verify_token`/`get_key`). Only
    /// `require_write`'s `jwt_verifier.is_some()` check matters for those
    /// tests, not the verifier's actual behavior.
    #[derive(Debug)]
    struct UnusedJwkService;

    #[async_trait]
    impl JWKService for UnusedJwkService {
        async fn get_key(
            &self,
            _kid: &str,
        ) -> Result<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
            unreachable!("test seeds the session directly; verify_token should never be called")
        }
    }

    /// A `jwt_verifier` that is `Some(..)` — i.e. "a verifier is configured" —
    /// without needing a real JWKS/signing setup, for tests exercising
    /// `require_write`'s dispatch-time gate on a directly-seeded session.
    fn verifier_present() -> Arc<Option<JwtVerifier>> {
        Arc::new(Some(JwtVerifier {
            jwk_service: Arc::new(UnusedJwkService),
            jwt_issuer: None,
            jwt_audience: None,
        }))
    }

    /// Wire-encodes a `MutableStore` command (key + value + key_type), matching
    /// `MutableStoreOp::parse`'s expected layout — see that type's own
    /// `test_parse`. The specific key/value/type don't matter for the
    /// write-permission-gate tests: a denial never reaches `handle_mutable_store`,
    /// and an allow uses a fresh in-memory store that accepts any well-formed op.
    fn mutable_store_payload() -> Bytes {
        let mut bytes = BytesMut::with_capacity(2 * size_of::<lore_base::types::Hash>() + 1);
        bytes.extend_from_slice(lore_base::types::Hash::hash_buffer(b"key").as_bytes());
        bytes.extend_from_slice(lore_base::types::Hash::hash_buffer(b"value").as_bytes());
        bytes.extend_from_slice(&[KeyType::Untyped as u8]);
        bytes.freeze()
    }

    /// Fill the session map to capacity then attempt one more `AuthorizeStart`,
    /// verifying the handler returns `SlowDown` and that `transform_protocol_error`
    /// classifies it the same way `stream_handler` would.
    #[tokio::test]
    async fn authorize_start_returns_slow_down_when_session_limit_reached() {
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("Failed to create stores");

        let service = StorageServiceV4::new(
            Arc::new(None),
            immutable_store.clone(),
            immutable_store.clone(),
            mutable_store,
            false,
        );

        let repo = random::<lore_revision::lore::RepositoryId>();

        // Fill the session map to capacity via the handler (jwt_verifier is None,
        // so each call goes straight to session_map.start with no I/O).
        for i in 0..MAX_CONCURRENT_SESSIONS {
            let result = service
                .run_request_handler(
                    AttributeMap::default().into(),
                    ParsedStorageRequestV4::AuthorizeStart {
                        repository: repo,
                        correlation_id: format!("fill-{i}"),
                        auth_token: vec![],
                    },
                )
                .await;
            assert!(result.is_ok(), "session {i} should succeed");
        }

        // One more must hit the limit.
        let err = service
            .run_request_handler(
                AttributeMap::default().into(),
                ParsedStorageRequestV4::AuthorizeStart {
                    repository: repo,
                    correlation_id: "over-limit".into(),
                    auth_token: vec![],
                },
            )
            .await
            .expect_err("expected SlowDown when session limit is reached");

        assert!(
            matches!(err, MessageHandleError::SessionLimitReached),
            "expected SessionLimitReached, got {err:?}"
        );

        // Verify stream_handler classification: SlowDown on the wire, not an internal
        // error, and suppressed from logging (same suppression path as SlowDown).
        let error_info = service.transform_protocol_error(&err);
        assert_eq!(
            error_info.response_error_code,
            QuicServiceError::SlowDown as QuicErrorStatus,
        );
        assert_eq!(error_info.message_handle_label, "SessionLimitReached");
        assert!(!error_info.is_internal_error);
        assert!(!error_info.is_appropriate_for_logging);
    }

    /// CR-018: the `require_write` gate on the `StorageCommand` dispatch path
    /// (Put/Copy/MutableStore/MutableCas/Verify(heal)). Sessions have no
    /// per-request token, so these seed a session directly via
    /// `session_map.start` (white-box: `tests` is a child module of the type
    /// it's testing, so private fields/session_map are reachable — see the
    /// testing guide's "White-box state via a same-file `#[cfg(test)] mod
    /// tests`" finding) rather than round-tripping a minted JWT through
    /// `AuthorizeStart`, since only the session's snapshotted `permissions`
    /// and the service's `jwt_verifier.is_some()`/`enforce_write_permission`
    /// flags drive the gate.
    mod require_write_dispatch_gate {
        use super::*;

        async fn service_with(
            jwt_verifier: Arc<Option<JwtVerifier>>,
            enforce_write_permission: bool,
        ) -> StorageServiceV4 {
            let (immutable_store, mutable_store, _execution) =
                test_store_create().await.expect("Failed to create stores");
            StorageServiceV4::new(
                jwt_verifier,
                immutable_store.clone(),
                immutable_store,
                mutable_store,
                enforce_write_permission,
            )
        }

        #[tokio::test]
        async fn read_only_session_denied_on_mutable_store_when_enforced() {
            let service = service_with(verifier_present(), true).await;
            let repo = random::<lore_revision::lore::RepositoryId>();
            let (session_id, _) = service
                .session_map
                .start(repo, "corr".into(), "user".into(), vec!["read".into()])
                .expect("seed read-only session");

            let err = service
                .run_request_handler(
                    AttributeMap::default().into(),
                    ParsedStorageRequestV4::StorageCommand {
                        session_id,
                        opcode: Command::MutableStore as u8,
                        payload: mutable_store_payload(),
                    },
                )
                .await
                .expect_err("read-only session must be denied a write op");

            assert!(
                matches!(err, MessageHandleError::AuthorizationFailure(_)),
                "expected AuthorizationFailure, got {err:?}"
            );

            // Wire classification: NotAuthorized, not silently downgraded.
            let error_info = service.transform_protocol_error(&err);
            assert_eq!(
                error_info.response_error_code,
                QuicServiceError::NotAuthorized as QuicErrorStatus,
            );
        }

        #[tokio::test]
        async fn write_session_allowed_on_mutable_store_when_enforced() {
            let service = service_with(verifier_present(), true).await;
            let repo = random::<lore_revision::lore::RepositoryId>();
            let (session_id, _) = service
                .session_map
                .start(
                    repo,
                    "corr".into(),
                    "user".into(),
                    vec!["read".into(), "write".into()],
                )
                .expect("seed write session");

            service
                .run_request_handler(
                    AttributeMap::default().into(),
                    ParsedStorageRequestV4::StorageCommand {
                        session_id,
                        opcode: Command::MutableStore as u8,
                        payload: mutable_store_payload(),
                    },
                )
                .await
                .expect("a session carrying write must pass the gate");
        }

        #[tokio::test]
        async fn read_only_session_allowed_when_enforcement_disabled() {
            // enforce_write_permission = false: the config flag itself, not
            // just the permission set, must gate the dispatch.
            let service = service_with(verifier_present(), false).await;
            let repo = random::<lore_revision::lore::RepositoryId>();
            let (session_id, _) = service
                .session_map
                .start(repo, "corr".into(), "user".into(), vec!["read".into()])
                .expect("seed read-only session");

            service
                .run_request_handler(
                    AttributeMap::default().into(),
                    ParsedStorageRequestV4::StorageCommand {
                        session_id,
                        opcode: Command::MutableStore as u8,
                        payload: mutable_store_payload(),
                    },
                )
                .await
                .expect("enforcement disabled must bypass the gate even for read-only");
        }

        #[tokio::test]
        async fn read_only_session_allowed_when_auth_is_off() {
            // jwt_verifier = None ("auth off"): has_verifier is false, so the
            // gate is a no-op regardless of enforce_write_permission or the
            // (here, still empty — no token to derive permissions from)
            // session permissions.
            let service = service_with(Arc::new(None), true).await;
            let repo = random::<lore_revision::lore::RepositoryId>();
            let (session_id, _) = service
                .session_map
                .start(repo, "corr".into(), "user".into(), vec![])
                .expect("seed session with no permissions");

            service
                .run_request_handler(
                    AttributeMap::default().into(),
                    ParsedStorageRequestV4::StorageCommand {
                        session_id,
                        opcode: Command::MutableStore as u8,
                        payload: mutable_store_payload(),
                    },
                )
                .await
                .expect("auth off must bypass the gate");
        }
    }
}

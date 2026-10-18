// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use lore_telemetry::user_agent_filter::UserAgentFilter;
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
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::authnz::repository_authorizer::VerifiedToken;
use crate::authnz::repository_authorizer::VerifiedTokenOwned;
use crate::grpc::caller_capabilities::CallerCapabilityPolicy;
use crate::grpc::caller_capabilities::admit_quic;
use crate::protocol::attribute_map::AttributeMap;
use crate::protocol::attribute_map::ConnectionId;
use crate::protocol::client_identify::ClientIdentify;
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
    ClientIdentify(ClientIdentify),
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
        MessageHandleError::OutcomeUnknown => QuicServiceError::OutcomeUnknown,
        // Storage status 200 = unsupported-client: a final pre-dispatch refusal.
        MessageHandleError::UnsupportedClient => QuicServiceError::ImplementationReserved,
        _ => QuicServiceError::Failed,
    }
}

#[lore_macro::test_pub]
pub struct StorageServiceV4 {
    jwt_verifier: Arc<Option<JwtVerifier>>,
    repository_authorizer: Arc<dyn RepositoryAuthorizer>,
    immutable_store: Arc<dyn ImmutableStore>,
    local_store: Arc<dyn ImmutableStore>,
    mutable_store: Arc<dyn MutableStore>,
    session_map: Arc<SessionMap>,
    enforce_write_permission: bool,
    user_agent_filter: Arc<UserAgentFilter>,
    caller_capability_policy: CallerCapabilityPolicy,
}

impl StorageServiceV4 {
    pub fn new(
        jwt_verifier: Arc<Option<JwtVerifier>>,
        repository_authorizer: Arc<dyn RepositoryAuthorizer>,
        immutable_store: Arc<dyn ImmutableStore>,
        local_store: Arc<dyn ImmutableStore>,
        mutable_store: Arc<dyn MutableStore>,
        enforce_write_permission: bool,
        user_agent_filter: Arc<UserAgentFilter>,
    ) -> Self {
        Self {
            jwt_verifier,
            repository_authorizer,
            immutable_store,
            local_store,
            mutable_store,
            session_map: Arc::new(SessionMap::default()),
            enforce_write_permission,
            user_agent_filter,
            caller_capability_policy: CallerCapabilityPolicy::default(),
        }
    }

    /// Set the caller-capability policy. Every production construction must call this
    /// with the configured policy; `new` keeps the compatible default.
    #[must_use]
    pub fn with_caller_capability_policy(mut self, policy: CallerCapabilityPolicy) -> Self {
        self.caller_capability_policy = policy;
        self
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

        if opcode == Command::ClientIdentify as u8 {
            return Ok(ParsedStorageRequestV4::ClientIdentify(
                ClientIdentify::parse(bytes, false)?,
            ));
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
        context: Arc<AttributeMap>,
        request: Self::ParsedRequestType,
    ) -> Result<Vec<Bytes>, Self::RequestHandlerError> {
        match request {
            ParsedStorageRequestV4::ClientIdentify(msg) => {
                msg.apply(&context, &self.user_agent_filter);
                Ok(vec![])
            }
            ParsedStorageRequestV4::AuthorizeStart {
                repository,
                correlation_id,
                auth_token,
            } => {
                let mut user_id = String::new();
                let mut permissions: Vec<String> = Vec::new();
                let mut grants = None;
                let mut token = None;

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

                    let verified = VerifiedToken {
                        raw: &token_str,
                        claims: &authorization,
                    };
                    grants = self
                        .repository_authorizer
                        .granted_access(Some(&verified), repository)
                        .await
                        .map_err(|status| {
                            MessageHandleError::AuthorizationFailure(status.message().to_string())
                        })?;
                    token = Some(Arc::new(verified.owned()));

                    permissions =
                        crate::auth::jwt::matching_permissions(&authorization, repository);
                    user_id = crate::util::get_user_id_from_token(Some(authorization));
                }

                let session_map = self.session_map.clone();
                match session_map.start(
                    repository,
                    correlation_id,
                    user_id,
                    permissions,
                    grants,
                    token,
                ) {
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
                let token = session.token.clone();
                let authorized_sources = session.authorized_sources.clone();
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
                // Caller admission runs first, before write authorization (contract order).
                admit_quic(self.caller_capability_policy, &parsed)?;
                match &parsed {
                    Req::Put(_) => self.require_write(&permissions, "Put")?,
                    Req::PutResolved(_) => self.require_write(&permissions, "PutResolved")?,
                    Req::Copy(_) => self.require_write(&permissions, "Copy")?,
                    Req::MutableStoreOp(_) => self.require_write(&permissions, "MutableStore")?,
                    Req::MutableCas(_) => self.require_write(&permissions, "MutableCas")?,
                    Req::Verify(verify) if verify.heal != 0 => {
                        self.require_write(&permissions, "Verify(heal)")?;
                    }
                    // Reads (and Verify without heal) are ungated.
                    Req::Verify(_)
                    | Req::Get(_)
                    | Req::GetResolved(_)
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
                        // The destination was checked at this session's start;
                        // a cross-partition source is this command's own
                        // question, asked with this session's token — another
                        // session's authorization on the connection must not
                        // vouch for it. A source this session's token already
                        // cleared is remembered, so a repeated copy from it
                        // skips the check.
                        if copy.source_repository != repository
                            && !authorized_sources.contains(&copy.source_repository)
                        {
                            let verified = token.as_deref().map(VerifiedTokenOwned::as_token);
                            self.repository_authorizer
                                .check_repository_access(
                                    verified.as_ref(),
                                    copy.source_repository,
                                    None,
                                )
                                .await
                                .map_err(|status| {
                                    MessageHandleError::AuthorizationFailure(
                                        status.message().to_string(),
                                    )
                                })?;
                            authorized_sources.insert(copy.source_repository);
                        }
                        handle_copy(
                            copy.source_repository,
                            copy.source_address,
                            repository,
                            copy.target_context,
                            correlation_id,
                            user_id,
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
                    crate::quic::storage_service::ParsedStorageRequest::GetResolved(resolved) => {
                        crate::protocol::storage::get_resolved::handle_get_resolved(
                            resolved.key,
                            resolved.context,
                            resolved.flags,
                            repository,
                            correlation_id,
                            user_id,
                            self.mutable_store.clone(),
                            self.immutable_store.clone(),
                        )
                        .await
                    }
                    crate::quic::storage_service::ParsedStorageRequest::PutResolved(resolved) => {
                        crate::protocol::storage::put_resolved::handle_put_resolved(
                            resolved.key,
                            resolved.put(),
                            resolved.address,
                            repository,
                            correlation_id,
                            user_id,
                            self.mutable_store.clone(),
                            self.immutable_store.clone(),
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

        let user_agent = context.get::<crate::protocol::client_identify::UserAgentValue>();
        build_storage_protocol_request_span(
            header.cmd,
            StorageProtocol::StorageV4,
            &connection_id,
            &repository_id,
            &correlation_id,
            &user_id,
            user_agent
                .as_ref()
                .map_or(crate::quic::NO_USER_AGENT, |v| v.0.as_ref()),
        )
    }
}

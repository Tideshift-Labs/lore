// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_revision::lore::RepositoryId;

use crate::protocol::storage::messages::MessageParseError;

#[lore_macro::test_pub]
const ACTION_START: u8 = 0;
#[lore_macro::test_pub]
const ACTION_STOP: u8 = 1;
// FORK-LOCAL (Tideshift, WP-124): a start that also carries the caller capability list,
// `... | caps_len(2, u16 LE) | caps(K, ASCII)` after the token, with no trailing bytes.
// A stock server answers this action byte with a parse error, so it fails closed.
#[lore_macro::test_pub]
const ACTION_START_DECLARED: u8 = 2;
// FORK-LOCAL (Tideshift, WP-124): the gRPC declaration header's byte limit.
#[lore_macro::test_pub]
const MAX_CALLER_CAPABILITIES_LEN: usize =
    crate::grpc::caller_capabilities::MAX_CAPABILITY_LIST_LEN;

// Minimum payload size for Authorize start:
// action(1) + repo_id(16) + corr_len(1) + auth_token_len(2) = 20
const AUTHORIZE_START_MIN_PAYLOAD: usize = 20;

#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizeStart {
    pub repository: RepositoryId,
    pub correlation_id: String,
    pub auth_token: Vec<u8>,
    /// FORK-LOCAL (Tideshift, WP-124): the declared capability list, unvalidated beyond
    /// ASCII. `None` for action 0; `Some` for action 2.
    pub caller_capabilities: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizeStop {
    pub session_id: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthorizeAction {
    Start(AuthorizeStart),
    Stop(AuthorizeStop),
}

impl AuthorizeStart {
    pub fn parse(bytes: Bytes) -> Result<Self, MessageParseError> {
        if bytes.len() < AUTHORIZE_START_MIN_PAYLOAD {
            return Err(MessageParseError::InvalidFieldLength);
        }

        let declared = match bytes[0] {
            ACTION_START => false,
            ACTION_START_DECLARED => true,
            _ => return Err(MessageParseError::ParseFailure("invalid action byte")),
        };

        let repository: RepositoryId = bytes.slice(1..17).into();
        let corr_len = bytes[17] as usize;
        let corr_end = 18 + corr_len;

        if bytes.len() < corr_end + 2 {
            return Err(MessageParseError::InvalidFieldLength);
        }

        let token_len = u16::from_le_bytes([bytes[corr_end], bytes[corr_end + 1]]) as usize;
        let token_start = corr_end + 2;

        let token_end = token_start + token_len;
        if bytes.len() < token_end {
            return Err(MessageParseError::InvalidFieldLength);
        }

        // Action 0 keeps upstream's tolerance of trailing bytes; action 2 is exact.
        let caller_capabilities = if declared {
            if bytes.len() < token_end + 2 {
                return Err(MessageParseError::InvalidFieldLength);
            }
            let caps_len = u16::from_le_bytes([bytes[token_end], bytes[token_end + 1]]) as usize;
            let caps_start = token_end + 2;
            if caps_len > MAX_CALLER_CAPABILITIES_LEN || bytes.len() != caps_start + caps_len {
                return Err(MessageParseError::InvalidFieldLength);
            }
            let caps = &bytes[caps_start..];
            if !caps.is_ascii() {
                return Err(MessageParseError::ParseFailure(
                    "caller capabilities are not ASCII",
                ));
            }
            let caps = std::str::from_utf8(caps).map_err(|_err| {
                MessageParseError::ParseFailure("caller capabilities are not ASCII")
            })?;
            Some(caps.to_owned())
        } else {
            None
        };

        // Allocate strings only after all length validations pass
        let correlation_id = if corr_len > 0 {
            String::from_utf8(bytes.slice(18..corr_end).to_vec()).map_err(|err| {
                tracing::debug!("Invalid UTF-8 in correlation_id: {err}");
                MessageParseError::ParseFailure("correlation_id is not valid UTF-8")
            })?
        } else {
            String::new()
        };

        let auth_token = bytes.slice(token_start..token_end).to_vec();

        Ok(Self {
            repository,
            correlation_id,
            auth_token,
            caller_capabilities,
        })
    }
}

impl AuthorizeStop {
    pub fn parse(session_id: u32, bytes: Bytes) -> Result<Self, MessageParseError> {
        if bytes.len() != 1 {
            return Err(MessageParseError::InvalidFieldLength);
        }
        if bytes[0] != ACTION_STOP {
            return Err(MessageParseError::ParseFailure("invalid action byte"));
        }
        if session_id == 0 {
            return Err(MessageParseError::ParseFailure(
                "session_id must be non-zero for stop",
            ));
        }
        Ok(Self { session_id })
    }
}

/// Parse an Authorize command payload, determining start vs stop from the action byte.
pub fn parse_authorize(
    session_id: u32,
    bytes: Bytes,
) -> Result<AuthorizeAction, MessageParseError> {
    if bytes.is_empty() {
        return Err(MessageParseError::InvalidFieldLength);
    }
    match bytes[0] {
        ACTION_START | ACTION_START_DECLARED => {
            if session_id != 0 {
                return Err(MessageParseError::ParseFailure(
                    "session_id must be 0 for authorize start",
                ));
            }
            Ok(AuthorizeAction::Start(AuthorizeStart::parse(bytes)?))
        }
        ACTION_STOP => Ok(AuthorizeAction::Stop(AuthorizeStop::parse(
            session_id, bytes,
        )?)),
        _ => Err(MessageParseError::ParseFailure("unrecognized action byte")),
    }
}

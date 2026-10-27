// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_revision::lore::RepositoryId;
use lore_server::protocol::storage::authorize::*;
use lore_server::protocol::storage::messages::MessageParseError;
use rand::random;
use zerocopy::IntoBytes;

fn build_start_payload(repo: RepositoryId, corr: &str, token: &[u8]) -> Bytes {
    let mut buf = Vec::new();
    buf.push(ACTION_START);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(corr.len() as u8);
    buf.extend_from_slice(corr.as_bytes());
    buf.extend_from_slice(&(token.len() as u16).to_le_bytes());
    buf.extend_from_slice(token);
    Bytes::from(buf)
}

#[test]
fn parse_start_valid() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "my-corr", b"my-token");
    let result = AuthorizeStart::parse(payload).unwrap();
    assert_eq!(result.repository, repo);
    assert_eq!(result.correlation_id, "my-corr");
    assert_eq!(result.auth_token, b"my-token");
}

#[test]
fn parse_start_empty_correlation() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "", b"tok");
    let result = AuthorizeStart::parse(payload).unwrap();
    assert_eq!(result.correlation_id, "");
}

#[test]
fn parse_start_empty_token() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "corr", b"");
    let result = AuthorizeStart::parse(payload).unwrap();
    assert!(result.auth_token.is_empty());
}

#[test]
fn parse_start_too_short() {
    let payload = Bytes::from(vec![0u8; 19]);
    assert_eq!(
        AuthorizeStart::parse(payload),
        Err(MessageParseError::InvalidFieldLength)
    );
}

#[test]
fn parse_start_bad_action() {
    let mut buf = vec![0u8; 20];
    buf[0] = 99; // bad action
    assert!(AuthorizeStart::parse(Bytes::from(buf)).is_err());
}

#[test]
fn parse_start_invalid_utf8_correlation() {
    let repo = random::<RepositoryId>();
    let mut buf = Vec::new();
    buf.push(ACTION_START);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(2); // corr_len = 2
    buf.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
    buf.extend_from_slice(&0u16.to_le_bytes()); // token_len = 0
    let result = AuthorizeStart::parse(Bytes::from(buf));
    assert!(result.is_err());
}

#[test]
fn parse_start_corr_len_exceeds_payload() {
    let repo = random::<RepositoryId>();
    let mut buf = Vec::new();
    buf.push(ACTION_START);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(200); // corr_len = 200 but only a few bytes follow
    buf.extend_from_slice(b"short");
    let result = AuthorizeStart::parse(Bytes::from(buf));
    assert_eq!(result, Err(MessageParseError::InvalidFieldLength));
}

#[test]
fn parse_start_token_len_exceeds_payload() {
    let repo = random::<RepositoryId>();
    let mut buf = Vec::new();
    buf.push(ACTION_START);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(1); // corr_len = 1
    buf.push(b'c');
    buf.extend_from_slice(&100u16.to_le_bytes()); // token_len = 100 but no bytes follow
    let result = AuthorizeStart::parse(Bytes::from(buf));
    assert_eq!(result, Err(MessageParseError::InvalidFieldLength));
}

#[test]
fn parse_stop_valid() {
    let payload = Bytes::from(vec![ACTION_STOP]);
    let result = AuthorizeStop::parse(42, payload).unwrap();
    assert_eq!(result.session_id, 42);
}

#[test]
fn parse_stop_session_id_zero() {
    let payload = Bytes::from(vec![ACTION_STOP]);
    assert!(AuthorizeStop::parse(0, payload).is_err());
}

#[test]
fn parse_stop_wrong_size() {
    let payload = Bytes::from(vec![ACTION_STOP, 0]);
    assert_eq!(
        AuthorizeStop::parse(1, payload),
        Err(MessageParseError::InvalidFieldLength)
    );
}

#[test]
fn parse_stop_bad_action() {
    let payload = Bytes::from(vec![99]);
    assert!(AuthorizeStop::parse(1, payload).is_err());
}

#[test]
fn parse_authorize_start() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "corr", b"tok");
    match parse_authorize(0, payload).unwrap() {
        AuthorizeAction::Start(s) => {
            assert_eq!(s.repository, repo);
            assert_eq!(s.correlation_id, "corr");
        }
        AuthorizeAction::Stop(_) => panic!("expected Start"),
    }
}

#[test]
fn parse_authorize_stop() {
    let payload = Bytes::from(vec![ACTION_STOP]);
    match parse_authorize(7, payload).unwrap() {
        AuthorizeAction::Stop(s) => assert_eq!(s.session_id, 7),
        AuthorizeAction::Start(_) => panic!("expected Stop"),
    }
}

#[test]
fn parse_authorize_start_nonzero_session_id() {
    let repo = random::<RepositoryId>();
    let payload = build_start_payload(repo, "corr", b"tok");
    assert!(parse_authorize(5, payload).is_err());
}

#[test]
fn parse_authorize_empty_payload() {
    assert_eq!(
        parse_authorize(0, Bytes::new()),
        Err(MessageParseError::InvalidFieldLength)
    );
}

// ---- WP-124 slice 1: action 2 (`ACTION_START_DECLARED`) --------------------------------------

/// Action 2 wire: `action | repo_id | corr_len | corr | token_len | token | caps_len | caps`.
/// `caps_len` is written from `caps_len_field` so a test can lie about it.
fn build_declared_payload(
    repo: RepositoryId,
    corr: &str,
    token: &[u8],
    caps: &[u8],
    caps_len_field: Option<u16>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(ACTION_START_DECLARED);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(corr.len() as u8);
    buf.extend_from_slice(corr.as_bytes());
    buf.extend_from_slice(&(token.len() as u16).to_le_bytes());
    buf.extend_from_slice(token);
    buf.extend_from_slice(&caps_len_field.unwrap_or(caps.len() as u16).to_le_bytes());
    buf.extend_from_slice(caps);
    buf
}

#[test]
fn action_codes_are_pinned() {
    assert_eq!(ACTION_START, 0);
    assert_eq!(ACTION_STOP, 1);
    assert_eq!(ACTION_START_DECLARED, 2);
    assert_eq!(MAX_CALLER_CAPABILITIES_LEN, 1024);
}

#[test]
fn parse_declared_start_valid() {
    let repo = random::<RepositoryId>();
    let payload = build_declared_payload(repo, "my-corr", b"my-token", b"outcome_unknown_v1", None);
    let result = AuthorizeStart::parse(Bytes::from(payload)).unwrap();
    assert_eq!(result.repository, repo);
    assert_eq!(result.correlation_id, "my-corr");
    assert_eq!(result.auth_token, b"my-token");
    assert_eq!(
        result.caller_capabilities.as_deref(),
        Some("outcome_unknown_v1")
    );
}

#[test]
fn action_zero_carries_no_capabilities() {
    let repo = random::<RepositoryId>();
    let result = AuthorizeStart::parse(build_start_payload(repo, "c", b"t")).unwrap();
    assert_eq!(result.caller_capabilities, None);
}

/// The grammar (ascending tokens, charset) belongs to `parse_capability_list`, not to the wire
/// parser: an empty list and an out-of-order list both parse, and the handler refuses them.
#[test]
fn parse_declared_start_does_not_check_the_grammar() {
    let repo = random::<RepositoryId>();
    for caps in [
        "",
        "z,a",
        "UPPER",
        "a,,b",
        "outcome_unknown_v1,outcome_unknown_v1",
    ] {
        let payload = build_declared_payload(repo, "c", b"t", caps.as_bytes(), None);
        let result = AuthorizeStart::parse(Bytes::from(payload)).unwrap();
        assert_eq!(
            result.caller_capabilities.as_deref(),
            Some(caps),
            "{caps:?}"
        );
    }
}

#[test]
fn parse_declared_start_accepts_the_maximum_caps_len() {
    let repo = random::<RepositoryId>();
    let caps = vec![b'a'; MAX_CALLER_CAPABILITIES_LEN];
    let payload = build_declared_payload(repo, "c", b"t", &caps, None);
    let result = AuthorizeStart::parse(Bytes::from(payload)).unwrap();
    assert_eq!(result.caller_capabilities.unwrap().len(), 1024);
}

#[test]
fn parse_declared_start_refuses_caps_len_over_the_limit() {
    let repo = random::<RepositoryId>();
    let caps = vec![b'a'; MAX_CALLER_CAPABILITIES_LEN + 1];
    let payload = build_declared_payload(repo, "c", b"t", &caps, None);
    assert_eq!(
        AuthorizeStart::parse(Bytes::from(payload)),
        Err(MessageParseError::InvalidFieldLength)
    );
    // The declared length alone is enough to refuse, whatever follows.
    let payload = build_declared_payload(repo, "c", b"t", b"a", Some(u16::MAX));
    assert_eq!(
        AuthorizeStart::parse(Bytes::from(payload)),
        Err(MessageParseError::InvalidFieldLength)
    );
}

#[test]
fn parse_declared_start_refuses_caps_len_past_the_end() {
    let repo = random::<RepositoryId>();
    let payload = build_declared_payload(repo, "c", b"t", b"abc", Some(10));
    assert_eq!(
        AuthorizeStart::parse(Bytes::from(payload)),
        Err(MessageParseError::InvalidFieldLength)
    );
}

/// An action 2 payload that ends right after the token has no `caps_len` at all.
#[test]
fn parse_declared_start_refuses_a_missing_caps_len() {
    let repo = random::<RepositoryId>();
    let mut payload = build_declared_payload(repo, "c", b"tok", b"", None);
    payload.truncate(payload.len() - 2);
    assert_eq!(
        AuthorizeStart::parse(Bytes::from(payload.clone())),
        Err(MessageParseError::InvalidFieldLength)
    );
    // One byte of `caps_len` is as short as none.
    payload.push(0);
    assert_eq!(
        AuthorizeStart::parse(Bytes::from(payload)),
        Err(MessageParseError::InvalidFieldLength)
    );
}

#[test]
fn parse_declared_start_refuses_a_short_payload() {
    // Below the action 0 minimum.
    let mut buf = vec![0u8; 19];
    buf[0] = ACTION_START_DECLARED;
    assert_eq!(
        AuthorizeStart::parse(Bytes::from(buf)),
        Err(MessageParseError::InvalidFieldLength)
    );
    // A corr_len that runs past the end.
    let repo = random::<RepositoryId>();
    let mut buf = Vec::new();
    buf.push(ACTION_START_DECLARED);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(200);
    buf.extend_from_slice(b"short");
    assert_eq!(
        AuthorizeStart::parse(Bytes::from(buf)),
        Err(MessageParseError::InvalidFieldLength)
    );
    // A token_len that runs past the end.
    let mut buf = Vec::new();
    buf.push(ACTION_START_DECLARED);
    buf.extend_from_slice(repo.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&100u16.to_le_bytes());
    assert_eq!(
        AuthorizeStart::parse(Bytes::from(buf)),
        Err(MessageParseError::InvalidFieldLength)
    );
}

/// Mutation probe (c): action 2 demands an exact length. Any byte after `caps` is refused,
/// including a single one and a zero byte.
#[test]
fn parse_declared_start_refuses_trailing_bytes() {
    let repo = random::<RepositoryId>();
    for trailing in [&[0u8][..], &[0xff][..], b"extra".as_slice()] {
        let mut payload = build_declared_payload(repo, "c", b"t", b"outcome_unknown_v1", None);
        payload.extend_from_slice(trailing);
        assert_eq!(
            AuthorizeStart::parse(Bytes::from(payload.clone())),
            Err(MessageParseError::InvalidFieldLength),
            "trailing {trailing:?}"
        );
        // And through the dispatcher.
        assert_eq!(
            parse_authorize(0, Bytes::from(payload)),
            Err(MessageParseError::InvalidFieldLength),
            "trailing {trailing:?} via parse_authorize"
        );
    }
    // The exact-length control: the same payload without the extra bytes parses.
    let payload = build_declared_payload(repo, "c", b"t", b"outcome_unknown_v1", None);
    assert!(AuthorizeStart::parse(Bytes::from(payload)).is_ok());
}

/// Upstream tolerance is kept for action 0: bytes after the token are ignored.
#[test]
fn parse_start_still_accepts_trailing_bytes_after_the_token() {
    let repo = random::<RepositoryId>();
    let mut payload = build_start_payload(repo, "corr", b"tok").to_vec();
    payload.extend_from_slice(b"ignored trailing bytes");
    let result = AuthorizeStart::parse(Bytes::from(payload.clone())).unwrap();
    assert_eq!(result.auth_token, b"tok");
    assert_eq!(result.caller_capabilities, None);
    assert!(matches!(
        parse_authorize(0, Bytes::from(payload)),
        Ok(AuthorizeAction::Start(_))
    ));
}

#[test]
fn parse_declared_start_refuses_non_ascii_caps() {
    let repo = random::<RepositoryId>();
    for caps in [&[0xffu8][..], "caf\u{e9}".as_bytes(), b"a\x80".as_slice()] {
        let payload = build_declared_payload(repo, "c", b"t", caps, None);
        assert!(
            matches!(
                AuthorizeStart::parse(Bytes::from(payload)),
                Err(MessageParseError::ParseFailure(_))
            ),
            "{caps:?}"
        );
    }
}

#[test]
fn parse_authorize_declared_start() {
    let repo = random::<RepositoryId>();
    let payload = build_declared_payload(repo, "corr", b"tok", b"a,outcome_unknown_v1", None);
    match parse_authorize(0, Bytes::from(payload)).unwrap() {
        AuthorizeAction::Start(s) => {
            assert_eq!(s.repository, repo);
            assert_eq!(s.correlation_id, "corr");
            assert_eq!(s.auth_token, b"tok");
            assert_eq!(
                s.caller_capabilities.as_deref(),
                Some("a,outcome_unknown_v1")
            );
        }
        AuthorizeAction::Stop(_) => panic!("expected Start"),
    }
}

#[test]
fn parse_authorize_declared_start_refuses_a_nonzero_session_id() {
    let repo = random::<RepositoryId>();
    let payload = build_declared_payload(repo, "corr", b"tok", b"outcome_unknown_v1", None);
    assert!(matches!(
        parse_authorize(5, Bytes::from(payload)),
        Err(MessageParseError::ParseFailure(_))
    ));
}

/// Bytes other than 0, 1, 2 stay refused.
#[test]
fn parse_authorize_refuses_unknown_action_bytes() {
    for action in [3u8, 4, 99, 255] {
        let mut buf = vec![0u8; 24];
        buf[0] = action;
        assert!(
            matches!(
                parse_authorize(0, Bytes::from(buf.clone())),
                Err(MessageParseError::ParseFailure(_))
            ),
            "action {action}"
        );
        assert!(AuthorizeStart::parse(Bytes::from(buf)).is_err());
    }
}

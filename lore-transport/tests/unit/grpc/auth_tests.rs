// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_transport::grpc::*;
use url::Url;

fn seeded_auth(authn: &str, authz: &str) -> parking_lot::RwLock<GRPCAuth> {
    parking_lot::RwLock::new(GRPCAuth {
        remote_domain: "example.com".to_string(),
        authentication_token: authn.to_string(),
        authorization_token: authz.to_string(),
        refresher: None,
    })
}

// CR-017(b): a refresh exchange that comes back empty (transient
// auth-endpoint outage) must not clobber a still-valid cached token --
// `inject_authorization` sends no header at all for an empty token, which
// would otherwise wedge every subsequent request.

#[test]
fn apply_refreshed_tokens_both_empty_leaves_previous_values() {
    let auth = seeded_auth("prev-authn", "prev-authz");
    apply_refreshed_tokens(&auth, String::new(), String::new());
    let auth = auth.read();
    assert_eq!(auth.authentication_token, "prev-authn");
    assert_eq!(auth.authorization_token, "prev-authz");
}

#[test]
fn apply_refreshed_tokens_both_non_empty_overwrites() {
    let auth = seeded_auth("prev-authn", "prev-authz");
    apply_refreshed_tokens(&auth, "new-authn".to_string(), "new-authz".to_string());
    let auth = auth.read();
    assert_eq!(auth.authentication_token, "new-authn");
    assert_eq!(auth.authorization_token, "new-authz");
}

#[test]
fn apply_refreshed_tokens_empty_authn_updates_only_authz() {
    let auth = seeded_auth("prev-authn", "prev-authz");
    apply_refreshed_tokens(&auth, String::new(), "new-authz".to_string());
    let auth = auth.read();
    assert_eq!(auth.authentication_token, "prev-authn");
    assert_eq!(auth.authorization_token, "new-authz");
}

#[test]
fn apply_refreshed_tokens_empty_authz_updates_only_authn() {
    let auth = seeded_auth("prev-authn", "prev-authz");
    apply_refreshed_tokens(&auth, "new-authn".to_string(), String::new());
    let auth = auth.read();
    assert_eq!(auth.authentication_token, "new-authn");
    assert_eq!(auth.authorization_token, "prev-authz");
}

#[test]
fn apply_refreshed_tokens_empty_over_empty_stays_empty() {
    let auth = seeded_auth("", "");
    apply_refreshed_tokens(&auth, String::new(), String::new());
    let auth = auth.read();
    assert_eq!(auth.authentication_token, "");
    assert_eq!(auth.authorization_token, "");
}

// CR-017(a): dropping the gRPC connection cache must sever the
// resurrection path -- a fresh `lock_connection` for the same URL after
// `drop_grpc_connections()` must be a distinct map entry, not the same
// one. Uses a unique URL per test and asserts only on that key's identity
// (never on global map size) since `CONNECTION_MAP` is process-global and
// shared with every other test in this crate's test binary.

#[tokio::test]
async fn drop_grpc_connections_clears_seeded_entry() {
    let url = Url::parse("http://cr017-test-host-a:41337").expect("valid test url");
    let first = lock_connection(&url).await;
    drop_grpc_connections().await;
    let second = lock_connection(&url).await;
    assert!(
        !Arc::ptr_eq(&first, &second),
        "expected a fresh map entry after drop_grpc_connections, got the same Arc"
    );
}

#[tokio::test]
async fn drop_grpc_connections_is_noop_when_map_absent() {
    // Calling drop twice in a row: the second call always finds the map
    // already `None` (the first call just cleared it), proving the
    // never-populated / already-cleared path doesn't panic.
    drop_grpc_connections().await;
    drop_grpc_connections().await;
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Authentication against an `OpenID` Connect provider.

pub mod discovery;

use std::sync::OnceLock;
use std::time::Duration;

use crate::user_agent;

/// Cap on any document read from an identity provider. Generous
/// beside any real discovery document or key set, so the only documents it refuses are
/// ones no identity provider would send.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// How much of a rejected response body reaches the log. The body is whatever the endpoint
/// chose to send, so it is neither trustworthy nor necessarily small.
pub const LOGGED_BODY_LIMIT: usize = 512;

/// Caps on a request to the identity provider, so a provider that accepts a connection and
/// never answers cannot stall a login.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Redirects followed within one origin before the request fails.
const MAX_REDIRECTS: usize = 10;

/// The head of a response body, for diagnostics.
pub fn body_excerpt(body: &str) -> String {
    match body.char_indices().nth(LOGGED_BODY_LIMIT) {
        Some((end, _)) => format!("{}… ({} bytes total)", &body[..end], body.len()),
        None => body.to_string(),
    }
}

/// One pooled client for every request to an identity provider.
///
/// Redirects are followed only within the origin of the request that started them. The
/// scheme is part of the origin, so a redirect can neither move the request to another
/// host nor downgrade it to plain http. A cross-origin redirect is returned to the caller
/// as the 3xx response.
fn http_client() -> Result<&'static reqwest::Client, reqwest::Error> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_webpki_certs(true)
        .tls_built_in_native_certs(true)
        .user_agent(user_agent())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let same_origin = attempt
                .previous()
                .first()
                .is_some_and(|first| first.origin() == attempt.url().origin());
            if !same_origin {
                attempt.stop()
            } else if attempt.previous().len() > MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    Ok(CLIENT.get_or_init(|| client))
}

/// Whether `url` may carry requests to an identity provider: `https`, or plain `http` to a
/// loopback host when `allow_loopback_http` is set. A URL carrying a username or password is
/// refused, so no credential reaches a log line or an error message through it.
fn is_permitted_url(url: &url::Url, allow_loopback_http: bool) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => true,
        "http" => allow_loopback_http && super::is_loopback_http_url(url),
        _ => false,
    }
}

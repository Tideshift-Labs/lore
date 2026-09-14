// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;

use super::*;
use crate::auth::jwk::JWKService;
use crate::auth::jwk::JWKServiceError;

const SECRET: &[u8] = b"namespace-state-interceptor-test-secret";
const ORG: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

struct CachedKey;

#[async_trait::async_trait]
impl JWKService for CachedKey {
    async fn get_key(&self, _: &str) -> Result<(DecodingKey, Algorithm), JWKServiceError> {
        Ok((DecodingKey::from_secret(SECRET), Algorithm::HS256))
    }
    fn get_cached_key(&self, _: &str) -> Option<(DecodingKey, Algorithm)> {
        Some((DecodingKey::from_secret(SECRET), Algorithm::HS256))
    }
    async fn refresh_key(
        &self,
        _: &str,
    ) -> Result<Option<(DecodingKey, Algorithm)>, JWKServiceError> {
        Ok(None)
    }
}

fn interceptor() -> JWTAuthnInterceptor {
    JWTAuthnInterceptor::new(&JwtVerifier {
        jwk_service: Arc::new(CachedKey),
        jwt_issuer: Some("https://issuer.example".into()),
        jwt_audience: Some(vec!["lore".into()]),
    })
}

fn signed(extra_claims: &str, secret: &[u8]) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = AuthorizationToken {
        issuer: "https://issuer.example".into(),
        user_id: "lorehub-control-plane".into(),
        audience: vec!["lore".into()],
        issued_at: now,
        expires: now + 300,
        is_service_account: Some(true),
        ..Default::default()
    };
    let mut payload = serde_json::to_string(&token).unwrap();
    payload.pop();
    payload.push_str(extra_claims);
    payload.push('}');
    let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let input = format!(
        "{}.{}",
        encoding.encode(br#"{"alg":"HS256","typ":"JWT","kid":"test"}"#),
        encoding.encode(payload)
    );
    let signature = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret),
        input.as_bytes(),
    );
    format!("{input}.{}", encoding.encode(signature.as_ref()))
}

fn request(token: &str) -> tonic::Request<()> {
    let mut request = tonic::Request::new(());
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_org_is_extracted_from_the_verified_bearer() {
    let token = signed(&format!(",\"org\":\"{ORG}\""), SECRET);
    let accepted = interceptor().call(request(&token)).unwrap();
    assert_eq!(
        accepted.extensions().get::<VerifiedServiceOrg>().unwrap().0,
        uuid::Uuid::parse_str(ORG).unwrap()
    );
    assert_eq!(
        accepted
            .extensions()
            .get::<AuthorizationToken>()
            .unwrap()
            .user_id,
        "lorehub-control-plane"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_malformed_and_duplicate_org_do_not_grant_org_binding() {
    for claims in [
        "".to_owned(),
        ",\"org\":\"not-a-uuid\"".into(),
        ",\"org\":null".into(),
        format!(",\"org\":\"{ORG}\",\"org\":\"{ORG}\""),
    ] {
        let token = signed(&claims, SECRET);
        let accepted = interceptor().call(request(&token)).unwrap();
        assert!(accepted.extensions().get::<AuthorizationToken>().is_some());
        assert!(
            accepted.extensions().get::<VerifiedServiceOrg>().is_none(),
            "claims {claims}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correctly_shaped_org_with_wrong_signature_is_rejected() {
    let token = signed(&format!(",\"org\":\"{ORG}\""), b"attacker-key");
    assert_eq!(
        interceptor().call(request(&token)).unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
}

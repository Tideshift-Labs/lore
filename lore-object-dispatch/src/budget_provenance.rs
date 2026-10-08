// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! The two budget provenance types a cell budget configuration may carry, and the consumer-side
//! rule that keeps each on the endpoint class its contract allows.
//!
//! `operator-selected-local-development-limit-v1` is a local fixture limit. It binds a local
//! `http://` endpoint and a window of at most 24 hours.
//!
//! `owner-decision-documented-provider-limit-v1` binds KV's 2026-08-31 ruling (the documented
//! DO Spaces limit of 800 operations per second per bucket, adopted without a paid
//! calibration), the provider region `do.sfo3`, its `https` Spaces endpoint, and a window of at
//! most 7 days. It is not provider-authoritative evidence: nothing here measures the provider.
//! It bounds only the operations the cell charges. Fragment GET is governed but deliberately
//! unmetered, so the bucket's total request rate can exceed the charged rate.
//! See the 2026-10-08 amendment in `lorehub/docs/contracts/object-store-budget-v1.md`.
//!
//! The consumer never sees the publication record, only the pin (`budget_revision`,
//! `budget_fence`) it charges against. So the documented type carries its tag and its hard expiry
//! in the revision token itself: `owner-decision-f<fence>-x<hardExpiresAtUnixMs>`. The publisher
//! refuses any other token for that type and refuses the tag on a local record, and the charge
//! still matches the stored revision byte for byte. The pin therefore names its provenance class,
//! which the consumer checks against its endpoint. The trust root is unchanged: the holder of the
//! cell maintenance credential publishes either type.

use crate::provider_client::BudgetPin;

pub const LOCAL_BUDGET_PROVENANCE: &str = "operator-selected-local-development-limit-v1";
pub const DOCUMENTED_PROVIDER_BUDGET_PROVENANCE: &str =
    "owner-decision-documented-provider-limit-v1";
/// The schema revision of a documented-provider budget configuration.
pub const DOCUMENTED_PROVIDER_BUDGET_REVISION: &str = "documented-provider-budget-policy-v1";
/// The ruling this type binds: the 2026-08-31 owner decision in the object-store budget contract.
pub const DOCUMENTED_PROVIDER_RULING_REFERENCE: &str =
    "object-store-budget-v1#owner-decision-2026-08-31";
pub const DOCUMENTED_PROVIDER_REGION: &str = "do.sfo3";
pub const DOCUMENTED_PROVIDER_ENDPOINT: &str = "https://sfo3.digitaloceanspaces.com";
pub const DOCUMENTED_PROVIDER_ENDPOINT_HOST: &str = "sfo3.digitaloceanspaces.com";
pub const DOCUMENTED_PROVIDER_MAX_OPERATIONS_PER_SECOND: u64 = 800;
pub const LOCAL_MAX_WINDOW_MS: i64 = 86_400_000;
pub const DOCUMENTED_PROVIDER_MAX_WINDOW_MS: i64 = 7 * 86_400_000;
/// The revision tag. A local configuration may not use it.
pub const DOCUMENTED_PROVIDER_REVISION_PREFIX: &str = "owner-decision-";

const LOCAL_HOSTS: [&str; 4] = ["minio", "localhost", "127.0.0.1", "[::1]"];

/// The provenance class a budget pin names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetPinProvenance {
    Local,
    DocumentedProvider { hard_expires_at_unix_ms: i64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BudgetProvenanceError {
    #[error("budget revision carries the documented-provider tag but not its exact grammar")]
    MalformedDocumentedRevision,
    #[error("a local budget pin may govern only a local http endpoint")]
    LocalBudgetOnNonLocalEndpoint,
    #[error("a documented-provider budget pin may govern only its bound https Spaces endpoint")]
    DocumentedBudgetOutsideBoundEndpoint,
}

/// The exact documented-provider revision token for one fence and hard expiry.
pub fn documented_provider_revision(fence: u64, hard_expires_at_unix_ms: i64) -> String {
    format!("{DOCUMENTED_PROVIDER_REVISION_PREFIX}f{fence}-x{hard_expires_at_unix_ms}")
}

fn canonical_decimal(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

/// Classify a revision token. A token without the tag is local. A tagged token must be exactly
/// [`documented_provider_revision`] for `fence`; anything else is refused, never read as local.
/// The tag is case-sensitive, so `OWNER-DECISION-...` is a local token, which the consumer then
/// refuses on any non-local endpoint.
pub fn classify_budget_revision(
    revision: &str,
    fence: u64,
) -> Result<BudgetPinProvenance, BudgetProvenanceError> {
    let Some(rest) = revision.strip_prefix(DOCUMENTED_PROVIDER_REVISION_PREFIX) else {
        return Ok(BudgetPinProvenance::Local);
    };
    let parsed = rest
        .strip_prefix('f')
        .and_then(|rest| rest.split_once("-x"))
        .and_then(|(fence_text, expiry_text)| {
            Some((
                canonical_decimal(fence_text)?,
                i64::try_from(canonical_decimal(expiry_text)?).ok()?,
            ))
        });
    match parsed {
        Some((parsed_fence, expiry)) if parsed_fence == fence && fence != 0 && expiry > 0 => {
            Ok(BudgetPinProvenance::DocumentedProvider {
                hard_expires_at_unix_ms: expiry,
            })
        }
        _ => Err(BudgetProvenanceError::MalformedDocumentedRevision),
    }
}

pub fn classify_budget_pin(pin: &BudgetPin) -> Result<BudgetPinProvenance, BudgetProvenanceError> {
    classify_budget_revision(&pin.revision, pin.fence)
}

/// A local endpoint: `http://`, one of the local hosts, an optional nonzero port, an optional
/// trailing slash, and nothing else.
pub fn is_local_endpoint(endpoint: &str) -> bool {
    endpoint
        .strip_prefix("http://")
        .and_then(|endpoint| endpoint.strip_suffix('/').or(Some(endpoint)))
        .is_some_and(|endpoint| {
            LOCAL_HOSTS.into_iter().any(|host| {
                endpoint == host
                    || endpoint.strip_prefix(host).is_some_and(|suffix| {
                        suffix.strip_prefix(':').is_some_and(|port| {
                            !port.starts_with('+') && port.parse::<u16>().is_ok_and(|port| port > 0)
                        })
                    })
            })
        })
}

/// The consumer-side rule. A local pin may govern only a local endpoint, so a fixture limit can
/// never govern real provider traffic. A documented-provider pin may govern only its bound
/// `https` Spaces endpoint, so it cannot stand in for a local fixture or for another provider.
/// `endpoint_url` is the object store's configured URL; `None` means the SDK default endpoint,
/// which is never local and never the bound one.
pub fn check_budget_pin_endpoint(
    pin: &BudgetPin,
    endpoint_url: Option<&str>,
    endpoint_host: &str,
) -> Result<BudgetPinProvenance, BudgetProvenanceError> {
    let provenance = classify_budget_pin(pin)?;
    match provenance {
        BudgetPinProvenance::Local => {
            if !endpoint_url.is_some_and(is_local_endpoint) || !LOCAL_HOSTS.contains(&endpoint_host)
            {
                return Err(BudgetProvenanceError::LocalBudgetOnNonLocalEndpoint);
            }
        }
        BudgetPinProvenance::DocumentedProvider { .. } => {
            if endpoint_url != Some(DOCUMENTED_PROVIDER_ENDPOINT)
                || endpoint_host != DOCUMENTED_PROVIDER_ENDPOINT_HOST
            {
                return Err(BudgetProvenanceError::DocumentedBudgetOutsideBoundEndpoint);
            }
        }
    }
    Ok(provenance)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(revision: &str, fence: u64) -> BudgetPin {
        BudgetPin {
            revision: revision.into(),
            fence,
        }
    }

    #[test]
    fn documented_revision_roundtrips_and_local_tokens_stay_local() {
        let token = documented_provider_revision(3, 1_767_225_600_000);
        assert_eq!(token, "owner-decision-f3-x1767225600000");
        assert_eq!(
            classify_budget_revision(&token, 3),
            Ok(BudgetPinProvenance::DocumentedProvider {
                hard_expires_at_unix_ms: 1_767_225_600_000
            })
        );
        for local in ["local-budget-1", "local-1", "budget-v1", "owner-decisionx"] {
            assert_eq!(
                classify_budget_revision(local, 1),
                Ok(BudgetPinProvenance::Local)
            );
        }
    }

    #[test]
    fn a_tagged_token_off_grammar_is_refused_not_read_as_local() {
        for (token, fence) in [
            ("owner-decision-f3-x1767225600000", 4),
            ("owner-decision-f03-x1767225600000", 3),
            ("owner-decision-f3-x01767225600000", 3),
            ("owner-decision-f3-x0", 3),
            ("owner-decision-f0-x1", 0),
            ("owner-decision-f3-x", 3),
            ("owner-decision-f3", 3),
            ("owner-decision-", 3),
            ("owner-decision-f3-x1767225600000-extra", 3),
            ("owner-decision-f3-x+1767225600000", 3),
            ("owner-decision-f3-x99999999999999999999", 3),
        ] {
            assert_eq!(
                classify_budget_revision(token, fence),
                Err(BudgetProvenanceError::MalformedDocumentedRevision),
                "{token}"
            );
        }
    }

    #[test]
    fn local_endpoint_grammar() {
        for local in [
            "http://minio:9000",
            "http://minio",
            "http://localhost:1/",
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
        ] {
            assert!(is_local_endpoint(local), "{local}");
        }
        for remote in [
            "https://minio:9000",
            "http://minio:0",
            "http://minio:+9000",
            "http://minio.example.com",
            "http://127.0.0.1.nip.io",
            DOCUMENTED_PROVIDER_ENDPOINT,
            "http://minio:9000/path",
        ] {
            assert!(!is_local_endpoint(remote), "{remote}");
        }
    }

    #[test]
    fn consumer_keeps_each_class_on_its_endpoint() {
        let local = pin("local-budget-1", 1);
        let documented = pin(&documented_provider_revision(1, 10_000), 1);
        assert_eq!(
            check_budget_pin_endpoint(&local, Some("http://minio:9000"), "minio"),
            Ok(BudgetPinProvenance::Local)
        );
        assert_eq!(
            check_budget_pin_endpoint(
                &documented,
                Some(DOCUMENTED_PROVIDER_ENDPOINT),
                DOCUMENTED_PROVIDER_ENDPOINT_HOST
            ),
            Ok(BudgetPinProvenance::DocumentedProvider {
                hard_expires_at_unix_ms: 10_000
            })
        );
        for (url, host) in [
            (
                Some(DOCUMENTED_PROVIDER_ENDPOINT),
                DOCUMENTED_PROVIDER_ENDPOINT_HOST,
            ),
            (Some("https://objects.example.com"), "objects.example.com"),
            (Some("http://minio:9000"), "objects.example.com"),
            (None, "minio"),
        ] {
            assert_eq!(
                check_budget_pin_endpoint(&local, url, host),
                Err(BudgetProvenanceError::LocalBudgetOnNonLocalEndpoint)
            );
        }
        for (url, host) in [
            (Some("http://minio:9000"), "minio"),
            (
                Some("https://nyc3.digitaloceanspaces.com"),
                "nyc3.digitaloceanspaces.com",
            ),
            (
                Some("http://sfo3.digitaloceanspaces.com"),
                DOCUMENTED_PROVIDER_ENDPOINT_HOST,
            ),
            (Some(DOCUMENTED_PROVIDER_ENDPOINT), "minio"),
            (None, DOCUMENTED_PROVIDER_ENDPOINT_HOST),
        ] {
            assert_eq!(
                check_budget_pin_endpoint(&documented, url, host),
                Err(BudgetProvenanceError::DocumentedBudgetOutsideBoundEndpoint)
            );
        }
        assert_eq!(
            check_budget_pin_endpoint(
                &pin("owner-decision-f2-x10000", 1),
                Some(DOCUMENTED_PROVIDER_ENDPOINT),
                DOCUMENTED_PROVIDER_ENDPOINT_HOST
            ),
            Err(BudgetProvenanceError::MalformedDocumentedRevision)
        );
    }
}

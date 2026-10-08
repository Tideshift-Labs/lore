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
use lore_proto::lore::domain::v1::DomainOperationAttemptReceiptGetRequest;
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
use crate::domain_receipt::DomainAttemptReceipt;
use crate::domain_receipt::DomainReceipt;
use crate::domain_receipt::DomainReceiptOutcome;
use crate::domain_receipt::DomainReceiptQuery;
use crate::domain_receipt::DomainReceiptState;
use crate::error::ProtocolError;
use crate::outcome::AttemptId;

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

    /// Look up the receipt for one attempt by the identity this client minted.
    pub async fn attempt_receipt_get(
        &self,
        attempt: &AttemptId,
    ) -> Result<DomainAttemptReceipt, ProtocolError> {
        attempt_receipt_get_impl(&self.client, &self.request_inflight, attempt).await
    }
}

/// Look up the receipt for one attempt by the identity this client minted.
///
/// One argument, because the server takes the namespace from the verified token rather than from
/// the request. That is the whole reason a released client can call this at all: it has to prove
/// who it is, which it can, and nothing about what it did, which it cannot.
async fn attempt_receipt_get_impl(
    client: &DomainOperationServiceClient<AuthorizedService>,
    request_inflight: &Arc<AtomicU64>,
    attempt: &AttemptId,
) -> Result<DomainAttemptReceipt, ProtocolError> {
    lore_debug!("Looking up the domain receipt for attempt {attempt}");

    let mut retry = grpc_retry();
    let response = loop {
        let _counter = RequestScopedCounter::new(request_inflight.clone());
        let mut client = client.clone();
        let request = DomainOperationAttemptReceiptGetRequest {
            client_attempt_id: Bytes::copy_from_slice(attempt.as_uuid().as_bytes()),
        };
        match client.domain_operation_attempt_receipt_get(request).await {
            Ok(response) => break response.into_inner(),
            Err(status) => handle_error(&mut retry, status).await?,
        }
    };

    // Decoded through the same rules the keyed lookup uses, deliberately. The two answers mean
    // the same things and a caller branches on them the same way; a second decode with its own
    // idea of what COMMITTED implies is how two paths come to disagree about one receipt.
    let state = decode_state(
        response.status,
        response.outcome,
        response.reason_version,
        &response.reason,
        response.from_future_marker,
        response.prepared_at_unix_millis,
        response.hard_expires_at_unix_millis,
    )?;
    Ok(DomainAttemptReceipt {
        state,
        method: response.method,
    })
}

/// CR-029 v1 requires `authorization_id` to equal the operation id, and the server refuses a
/// request where it does not. Deriving it here rather than carrying it on the query keeps the
/// disagreement unrepresentable. A v2 that separates the two identities has to put the field
/// back on [`DomainReceiptQuery`]; this is the site that would have to change.
#[lore_macro::test_pub]
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
#[lore_macro::test_pub]
fn decode_receipt(
    response: DomainOperationReceiptGetResponse,
) -> Result<DomainReceipt, ProtocolError> {
    let state = decode_state(
        response.status,
        response.outcome,
        response.reason_version,
        &response.reason,
        response.from_future_marker,
        response.prepared_at_unix_millis,
        response.hard_expires_at_unix_millis,
    )?;

    Ok(DomainReceipt {
        state,
        verification_nonce: response.verification_nonce,
        bound_fields_digest: response.bound_fields_digest,
        consumed_ticket_sha256: response.consumed_ticket_sha256,
        authorization_revision: response.authorization_revision,
    })
}

/// The one place a wire status becomes a [`DomainReceiptState`].
///
/// Shared by both lookups on purpose. They ask different questions and are answered by different
/// RPCs, but a `COMMITTED` means the same thing to each, and two decoders with their own reading
/// of that is how one receipt comes to have two verdicts.
#[allow(clippy::too_many_arguments)]
fn decode_state(
    status: i32,
    outcome: i32,
    reason_version: Option<u32>,
    reason: &str,
    from_future_marker: bool,
    prepared_at_unix_millis: Option<i64>,
    hard_expires_at_unix_millis: Option<i64>,
) -> Result<DomainReceiptState, ProtocolError> {
    let status = DomainOperationReceiptStatus::try_from(status).map_err(|_err| {
        ProtocolError::internal(format!(
            "receipt lookup returned unrecognised status {status}"
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
            let (Some(prepared_at_unix_millis), Some(hard_expires_at_unix_millis)) =
                (prepared_at_unix_millis, hard_expires_at_unix_millis)
            else {
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
            outcome: decode_outcome(outcome, reason_version, reason)?,
            from_future_marker,
        },
        DomainOperationReceiptStatus::Mismatch => DomainReceiptState::Mismatch,
        DomainOperationReceiptStatus::Expired => DomainReceiptState::Expired,
        DomainOperationReceiptStatus::ExpiredOrUnknown => DomainReceiptState::ExpiredOrUnknown,
        DomainOperationReceiptStatus::NotFound => DomainReceiptState::NotFound,
    };

    Ok(state)
}

/// Read the outcome of a committed receipt.
///
/// A committed receipt without a decisive outcome is refused rather than softened into one. The
/// caller's whole reason for asking is that it does not know what happened, so an outcome it has
/// to guess at is worth less than no answer at all.
fn decode_outcome(
    outcome: i32,
    reason_version: Option<u32>,
    reason: &str,
) -> Result<DomainReceiptOutcome, ProtocolError> {
    let outcome = DomainOperationOutcome::try_from(outcome).map_err(|_err| {
        ProtocolError::internal(format!(
            "committed receipt carried unrecognised outcome {outcome}"
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
            let Some(reason_version) = reason_version else {
                return Err(ProtocolError::internal(
                    "committed NOT_APPLIED receipt carried no reason version",
                ));
            };
            Ok(DomainReceiptOutcome::NotApplied {
                reason_version,
                reason: reason.to_owned(),
            })
        }
        DomainOperationOutcome::Unspecified => Err(ProtocolError::internal(
            "committed receipt carried an unspecified outcome",
        )),
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The frozen `StreamResetService` (WP-119 Step C).
//!
//! WP-110 detects a broker reset and calls this once per detection, with bounded
//! retry. WP-119 owns everything on this side: authentication, the canonical
//! derivation check, the durable receipt transaction, the stored
//! acknowledgement, the fence, and the requeue.
//!
//! # The order is the security property
//!
//! The contract fixes it, and the fixed order is the reason a key-probing caller
//! learns nothing:
//!
//! 1. **authentication** — a valid internal-service mTLS identity, with the
//!    stable emitter principal derived from the SPIFFE ID / SAN rather than from
//!    the leaf certificate, because certificates rotate and the authorization
//!    this record replays an ack to must outlive a rotation;
//! 2. **authorization** — that principal must map to the request's own cell;
//! 3. **derivation** — the fingerprint must recompute from the supplied
//!    correctness fields and the detection ID must be its `UUIDv5`. Validated
//!    exactly once, here, before any durable lookup: a derivation failure is
//!    `MALFORMED_REPORT_V1`, never a successor or mismatch failure;
//! 4. **stored-record comparison** — an exact retry from the same emitter and
//!    cell returns the byte-identical stored ack, *before* current-placement and
//!    current-old validation and still valid after placement drift;
//! 5. **current placement**, then **current old stream**, then **successor
//!    validity** — only for a previously unseen detection.
//!
//! Putting authentication and authorization ahead of the stored-record
//! comparison is what keeps a caller from distinguishing an existing detection
//! from an absent one. Putting the lookup ahead of placement validation is what
//! keeps a correct emitter's retry from failing forever after the cell's
//! placement moved.
//!
//! # What acknowledging means
//!
//! An ack is sent only after the durable transaction commits, and after the
//! retained unsafe rows for the old epoch have been requeued. Every rejection
//! path mutates nothing at all: no fence, no readiness change, no generation
//! allocated, no evidence, and never another cell.

use lore_postgres::domain::outbox::relay;
use lore_postgres::domain::outbox::reset;
use lore_postgres::domain::outbox::reset::AckInputs;
use lore_postgres::domain::outbox::reset::ResetAcceptance;
use lore_postgres::domain::outbox::reset::ResetReport;
use lore_postgres::pool::Pool;
use tonic::async_trait;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::event_relay::metrics;
use crate::event_relay::reset_budget;
use crate::event_relay::reset_budget::Charge;
use crate::event_relay::reset_budget::ReportBudget;
use crate::event_relay::reset_budget::UNAUTHENTICATED_KEY;
use crate::event_relay::reset_wire::RESET_SCHEMA_VERSION;
use crate::event_relay::reset_wire::ResetReasonV1;
use crate::event_relay::reset_wire::ResetReportErrorV1;
use crate::event_relay::reset_wire::StoredAck;
use crate::event_relay::reset_wire::StreamResetAckV1;
use crate::event_relay::reset_wire::StreamResetReportV1;
use crate::event_relay::reset_wire::StreamResetService;
use crate::event_relay::reset_wire::detection_id;
use crate::event_relay::reset_wire::encode;
use crate::event_relay::reset_wire::reset_fingerprint;

/// The stored reset state that still owes a requeue. Mirrors `lore_postgres`'s
/// own constant so the comparison is against the persisted vocabulary rather
/// than a literal; a unit test pins the two together.
#[lore_macro::test_pub]
const RESET_STATE_IN_PROGRESS: &str = "reset_in_progress";

/// The SPIFFE path segment that names a cell.
///
/// PIN(WP-119): the notification-plane contract requires the emitter principal
/// to "map currently to the request `cell_id`" but does not fix the mapping's
/// shape, and this fork has no prior internal-service mTLS principal to follow —
/// `grpc_internal_server.rs` configures a client CA root and never inspects the
/// resulting identity. The convention adopted here is a SPIFFE path containing a
/// `/cell/<cell_id>/` segment pair, which is the shape SPIFFE workload
/// registration already uses for per-tenant workloads. An explicit
/// principal-to-cell table is the alternative and is deferred: it needs a
/// configuration surface that does not exist yet, and inventing one here would
/// freeze a shape the deployment has not chosen.
const SPIFFE_CELL_SEGMENT: &str = "cell";

/// How many retained unsafe rows one accepted reset may requeue before the
/// requeue is abandoned as non-convergent. Well above CR-032's one-million-row
/// admission ceiling; the store's own sweep is bounded per batch.
const RESET_REQUEUE_LOG_THRESHOLD: u64 = 100_000;

/// The service. One per cell, holding the relay's own pool.
pub struct StreamResetHandler {
    pool: Pool,
    cell_id: String,
    /// Per-emitter diagnostic budget (WP-119 Phase 8).
    ///
    /// Rate-limits the **logging** of rejected reports, never a verdict. See
    /// [`super::reset_budget`] for why the stronger design — refusing an
    /// over-budget caller outright — is deliberately not taken.
    budget: ReportBudget,
}

impl std::fmt::Debug for StreamResetHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The pool has no useful Debug and would print connection detail into a
        // log line; the cell identity is the whole of what identifies this
        // service.
        f.debug_struct("StreamResetHandler")
            .field("cell_id", &self.cell_id)
            .finish_non_exhaustive()
    }
}

impl StreamResetHandler {
    /// Build the service for one cell.
    pub fn new(pool: Pool, cell_id: String) -> Self {
        Self {
            pool,
            cell_id,
            budget: ReportBudget::default(),
        }
    }

    /// Accept, replay, or reject one report. See the module documentation for
    /// the fixed order and why it is the security property.
    ///
    /// The budget charged on the failure paths below observes the outcome and
    /// changes nothing about it. Every `?` here returns the same status it
    /// always did, in the same order, whether or not the emitter is
    /// quarantined.
    async fn serve(
        &self,
        request: tonic::Request<StreamResetReportV1>,
    ) -> Result<tonic::Response<StoredAck>, tonic::Status> {
        // 1. Authentication, before anything reads the body. A failure here has
        //    no principal to key a budget on, so it charges the shared
        //    unauthenticated bucket.
        let principal = match authenticate(&request) {
            Ok(principal) => principal,
            Err(status) => {
                self.note_rejection(UNAUTHENTICATED_KEY, metrics::RESET_UNAUTHENTICATED, || {
                    "a stream reset report failed authentication".to_owned()
                });
                return Err(status);
            }
        };
        let report = request.into_inner();
        // 2. Authorization, before the stored-record comparison, so a
        //    key-probing caller cannot tell an existing detection from an
        //    absent one.
        if let Err(status) = authorize(&self.cell_id, &principal, &report.cell_id) {
            self.note_rejection(&principal, metrics::RESET_UNAUTHORIZED, || {
                "a stream reset report was refused by the cell authorization check".to_owned()
            });
            return Err(status);
        }
        // 3. Derivation, exactly once, before any durable lookup.
        let report = match validate_and_convert(&report) {
            Ok(report) => report,
            Err(status) => {
                self.note_rejection(&principal, metrics::RESET_MALFORMED, || {
                    "a stream reset report failed its canonical derivation check".to_owned()
                });
                return Err(status);
            }
        };
        self.receipt(report, principal).await
    }

    /// Charge one rejection against its emitter's diagnostic budget, and log it
    /// at the volume that budget allows.
    ///
    /// `detail` is a closure so an over-budget rejection does not pay to format
    /// a message nothing will print — which is the cost this exists to bound.
    ///
    /// Returns nothing on purpose. There is no verdict here for a caller to
    /// branch on: every call site has already decided its status, and a return
    /// value would invite a future edit to gate that status on the budget.
    fn note_rejection<F>(&self, principal: &str, outcome: &'static str, detail: F)
    where
        F: FnOnce() -> String,
    {
        metrics::record_reset_report(outcome);
        match self.budget.charge(principal, std::time::Instant::now()) {
            Charge::Report => {
                warn!(cell_id = %self.cell_id, %principal, outcome, "{}", detail());
            }
            Charge::Quarantining => {
                // The protected line. It is emitted even though the emitter has
                // just crossed its budget, because it is the record that
                // explains every rejection that follows it — an operator
                // reading a suddenly quiet log needs to find this.
                warn!(
                    cell_id = %self.cell_id,
                    %principal,
                    outcome,
                    budget = reset_budget::REJECTION_BUDGET,
                    refill_seconds = reset_budget::REJECTION_REFILL_INTERVAL.as_secs(),
                    "{}; this emitter has exhausted its diagnostic budget and further rejections \
                     will be counted rather than logged. Its reports are still served unchanged.",
                    detail()
                );
            }
            Charge::Quarantined => {
                metrics::record_quarantined_reset_report(outcome);
                debug!(cell_id = %self.cell_id, %principal, outcome, "quarantined reset rejection");
            }
        }
    }

    /// Clear an emitter's budget after it succeeds.
    fn note_success(&self, principal: &str) {
        self.budget.forgive(principal);
    }
}

/// Derive the caller's stable emitter principal from its peer certificate.
///
/// Returns `UNAUTHENTICATED_REPORT_V1` when the connection carries no peer
/// certificate at all, which is the state of an internal endpoint configured
/// with `verify_client_certs = false`. That is a deliberate refusal rather than
/// a fallback: this RPC installs a cell-wide fence, and there is no weaker
/// identity that may do so.
///
/// A free function rather than a method because it touches no handler state.
/// That is not tidiness: it is what lets the refusal be tested without a
/// database pool, and a test that cannot be written without one tends not to be
/// written.
#[lore_macro::test_pub]
fn authenticate<T>(request: &tonic::Request<T>) -> Result<String, tonic::Status> {
    let Some(certs) = request.peer_certs() else {
        return Err(ResetReportErrorV1::UnauthenticatedReport.status());
    };
    let Some(leaf) = certs.first() else {
        return Err(ResetReportErrorV1::UnauthenticatedReport.status());
    };
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|error| {
        // `debug!`, not `warn!`: the caller-facing refusal below is what the
        // per-emitter diagnostic budget rate-limits, and a `warn!` here would
        // route around it — an unauthenticated flood would fill the log through
        // this line while every budgeted line stayed silent.
        debug!(%error, "a stream reset caller presented an unparseable leaf certificate");
        ResetReportErrorV1::UnauthenticatedReport.status()
    })?;
    // The SAN's URI entry, not the subject DN and not the certificate itself.
    // The contract is explicit that the principal comes from the SPIFFE ID /
    // SAN, because a fingerprint or serial would change on every rotation and
    // invalidate the authorization a stored ack replays under.
    let Ok(Some(san)) = parsed.tbs_certificate.subject_alternative_name() else {
        return Err(ResetReportErrorV1::UnauthenticatedReport.status());
    };
    san.value
        .general_names
        .iter()
        .find_map(|name| match name {
            x509_parser::extensions::GeneralName::URI(uri) => Some((*uri).to_string()),
            _ => None,
        })
        .ok_or_else(|| ResetReportErrorV1::UnauthenticatedReport.status())
}

/// Whether this principal may report resets for this cell.
///
/// Cross-cell is `CROSS_CELL_REPORT_V1` and reaching this service at all without
/// a cell segment is `UNAUTHORIZED_REPORT_V1`. Both are `PERMISSION_DENIED` on
/// the wire; the distinction is in the detail, which is what an operator reads.
///
/// **Both halves are checked.** The principal must name this cell *and* the
/// report must name this cell. Either check alone would let a
/// correctly-authenticated emitter install a fence on a cell it does not belong
/// to.
#[lore_macro::test_pub]
fn authorize(cell_id: &str, principal: &str, request_cell: &str) -> Result<(), tonic::Status> {
    let Some(principal_cell) = spiffe_cell(principal) else {
        debug!(%cell_id, "a stream reset caller's principal names no cell segment");
        return Err(ResetReportErrorV1::UnauthorizedReport.status());
    };
    if principal_cell != cell_id || request_cell != cell_id {
        debug!(%cell_id, "a stream reset report named another cell");
        return Err(ResetReportErrorV1::CrossCellReport.status());
    }
    Ok(())
}

/// The cell a SPIFFE ID names, or `None`.
///
/// Looks for a `cell/<id>` pair anywhere in the path, so
/// `spiffe://tideshift/cell/sfo3-cell-a/wp110` and
/// `spiffe://tideshift/region/sfo3/cell/sfo3-cell-a` both resolve. Nothing here
/// parses the trust domain: the connection already proved the certificate chains
/// to this endpoint's configured client CA root, and re-deriving trust from a
/// string the certificate carries would be weaker than the proof already made.
#[lore_macro::test_pub]
fn spiffe_cell(principal: &str) -> Option<&str> {
    let path = principal.strip_prefix("spiffe://")?;
    let (_trust_domain, path) = path.split_once('/')?;
    let mut segments = path.split('/');
    while let Some(segment) = segments.next() {
        if segment == SPIFFE_CELL_SEGMENT {
            return segments.next().filter(|cell| !cell.is_empty());
        }
    }
    None
}

/// Validate the request's shape and canonical derivation, and turn it into the
/// storage-side report.
///
/// Every failure here is `MALFORMED_REPORT_V1`. That is the contract's
/// classification and it is load-bearing: a fingerprint that does not recompute
/// is malformed input, not a mismatch with a stored record and not an invalid
/// successor, and returning either of those would tell a caller something about
/// state it has not been authorized to learn.
#[lore_macro::test_pub]
fn validate_and_convert(request: &StreamResetReportV1) -> Result<ResetReport, tonic::Status> {
    let malformed = |what: &str| -> tonic::Status {
        tonic::Status::new(
            ResetReportErrorV1::MalformedReport.code(),
            format!("{}: {what}", ResetReportErrorV1::MalformedReport.detail()),
        )
    };

    if request.schema_version != RESET_SCHEMA_VERSION {
        return Err(malformed("schema_version must be exactly 1"));
    }
    if request.reason_code == ResetReasonV1::Unspecified as i32 {
        // The zero value exists because proto3 requires one and never appears in
        // a valid report, so it is malformed rather than an unknown reason.
        return Err(malformed(
            "reason_code is RESET_REASON_V1_UNSPECIFIED, which never appears in a valid report",
        ));
    }
    if ResetReasonV1::try_from(request.reason_code).is_err() {
        return Err(malformed("reason_code is not a ResetReasonV1 value"));
    }
    if request.reset_fingerprint.len() != 32 {
        return Err(malformed("reset_fingerprint must be exactly 32 bytes"));
    }

    let recomputed = reset_fingerprint(
        &request.broker_reset_identity,
        &request.cell_id,
        &request.old_stream_identity,
        request.old_stream_epoch,
        &request.new_stream_identity,
        request.new_stream_epoch,
    );
    if recomputed.as_slice() != request.reset_fingerprint.as_ref() {
        return Err(malformed(
            "reset_fingerprint does not recompute from the supplied correctness fields",
        ));
    }
    if detection_id(&recomputed) != request.detection_id {
        return Err(malformed(
            "detection_id is not the UUIDv5 of the supplied reset_fingerprint",
        ));
    }

    // The epochs are `uint64` on the wire and `bigint` in storage. A value above
    // `i64::MAX` is representable in the contract's fixture space (the
    // `max-epoch-boundary` vector is `u64::MAX`) and is not storable here, so it
    // is refused explicitly rather than wrapping into a negative epoch that
    // every `>= 1` CHECK would then reject with an unrelated message.
    let old_stream_epoch = i64::try_from(request.old_stream_epoch)
        .map_err(|_err| malformed("old_stream_epoch exceeds the storable range"))?;
    let new_stream_epoch = i64::try_from(request.new_stream_epoch)
        .map_err(|_err| malformed("new_stream_epoch exceeds the storable range"))?;
    let placement_revision = i64::try_from(request.placement_revision)
        .map_err(|_err| malformed("placement_revision exceeds the storable range"))?;

    let report = ResetReport {
        detection_id: request.detection_id.clone(),
        reset_fingerprint: recomputed,
        broker_reset_identity: request.broker_reset_identity.clone(),
        cell_id: request.cell_id.clone(),
        placement_revision,
        old_stream_identity: request.old_stream_identity.clone(),
        old_stream_epoch,
        new_stream_identity: request.new_stream_identity.clone(),
        new_stream_epoch,
        reason_code: request.reason_code,
        detected_at_unix_ms: request.detected_at_unix_ms,
    };
    // Bounds the storage side owns. Reported as malformed here, because from the
    // caller's point of view an over-long field is exactly that.
    reset::validate_report(&report).map_err(|error| malformed(&error.to_string()))?;
    Ok(report)
}

/// Build the acknowledgement this receipt will store.
///
/// Nothing on this path is spawned. The receipt is synchronous with the RPC by
/// contract and the requeue must complete before the acknowledgement, so "do it
/// in the background" — the obvious optimisation — would break the ordering the
/// contract fixes.
#[lore_macro::test_pub]
fn build_ack(inputs: &AckInputs) -> Vec<u8> {
    encode(&StreamResetAckV1 {
        schema_version: RESET_SCHEMA_VERSION,
        cell_id: inputs.cell_id.clone(),
        detection_id: inputs.detection_id.clone(),
        reset_fingerprint: bytes::Bytes::copy_from_slice(&inputs.reset_fingerprint),
        // `reset_generation` is `uint64` on the wire and `bigint` in storage.
        // The counter starts at 1 and increments under a `>= 1` CHECK, so a
        // negative value is unreachable. `try_from` rather than `as`: an
        // impossible value becomes a visibly wrong 0 rather than a plausible
        // huge positive one that a reader would take at face value.
        reset_generation: u64::try_from(inputs.reset_generation).unwrap_or(0),
        evidence_id: inputs.evidence_id.clone(),
        persisted_at_unix_ms: inputs.persisted_at_unix_ms,
    })
}

impl StreamResetHandler {
    /// Steps 4 through 7: the durable lookup, the validation only an unseen
    /// detection reaches, the one receipt transaction, and the requeue that
    /// must finish before the acknowledgement.
    async fn receipt(
        &self,
        report: ResetReport,
        principal: String,
    ) -> Result<tonic::Response<StoredAck>, tonic::Status> {
        let mut client = self.pool.get().await.map_err(|error| {
            error!(%error, "the stream reset service could not take a relay connection");
            tonic::Status::unavailable("the outbox relay database is unavailable")
        })?;

        // 4-7. Lookup, then validation, then the one durable transaction.
        let acceptance = reset::accept_reset(&mut client, &report, &principal, build_ack)
            .await
            .map_err(|error| {
                error!(%error, "the stream reset receipt transaction failed");
                // A failure here left nothing committed, so the honest answer is
                // that the outcome is unknown to the caller and the same report
                // may be sent again. Its bounded retry is what resolves it.
                tonic::Status::unavailable(format!("the stream reset receipt failed: {error}"))
            })?;

        match acceptance {
            ResetAcceptance::Replayed { stored } => {
                // A replay is NOT just an ack lookup. The receipt transaction
                // and the requeue are two steps, and only the first is atomic:
                // a receipt that committed and whose requeue then failed
                // returned `UNAVAILABLE`, and this retry is how that failure is
                // resolved. Returning the stored ack without re-driving the
                // requeue would leave every retained unsafe row for the void
                // epoch `broker_accepted` forever, silently skipping the
                // contract's step 4 while reporting success.
                //
                // Re-driving is safe because the requeue is idempotent by
                // predicate: it matches only rows still `broker_accepted` on the
                // old stream and epoch, so a second run over a completed reset
                // moves nothing. It is gated on the fence still standing, so an
                // ordinary duplicate report on a long-since-cleared reset stays
                // a cheap lookup.
                if stored.state == RESET_STATE_IN_PROGRESS {
                    let requeued = relay::requeue_unsafe_for_epoch_reset(
                        &mut client,
                        &stored.old_stream_identity,
                        stored.old_stream_epoch,
                    )
                    .await
                    .map_err(|error| {
                        error!(
                            %error,
                            cell_id = %self.cell_id,
                            reset_generation = stored.reset_generation,
                            "the epoch-reset requeue failed again on a replayed report"
                        );
                        tonic::Status::unavailable(format!(
                            "the stream reset is recorded but its requeue failed: {error}"
                        ))
                    })?;
                    if requeued > 0 {
                        warn!(
                            cell_id = %self.cell_id,
                            reset_generation = stored.reset_generation,
                            requeued,
                            "a replayed stream reset report completed a requeue that an earlier \
                             attempt had left unfinished"
                        );
                    }
                }
                self.note_success(&principal);
                metrics::record_reset_report(metrics::RESET_REPLAYED);
                info!(
                    cell_id = %self.cell_id,
                    reset_generation = stored.reset_generation,
                    "replayed the stored acknowledgement for an equivalent stream reset report"
                );
                Ok(tonic::Response::new(StoredAck(stored.ack_bytes)))
            }
            ResetAcceptance::Accepted {
                stored,
                membership_version,
                retired_generations,
                old_stream_identity,
                old_stream_epoch,
            } => {
                info!(
                    cell_id = %self.cell_id,
                    reset_generation = stored.reset_generation,
                    membership_version,
                    retired_generations,
                    "accepted a stream reset; requeueing retained unsafe rows for the old epoch"
                );
                // The requeue is outside the receipt transaction because it is a
                // multi-batch sweep, and it is before the acknowledgement
                // because the contract orders it that way: the caller may not
                // learn the reset was accepted until every retained unsafe row
                // is eligible for republication under the new epoch.
                let requeued = relay::requeue_unsafe_for_epoch_reset(
                    &mut client,
                    &old_stream_identity,
                    old_stream_epoch,
                )
                .await
                .map_err(|error| {
                    error!(
                        %error,
                        cell_id = %self.cell_id,
                        reset_generation = stored.reset_generation,
                        "the epoch-reset requeue failed after the receipt committed"
                    );
                    // The fence stands and the evidence is durable, so a retry
                    // of the same report replays the stored ack and re-drives
                    // the requeue. Failing the RPC rather than acknowledging is
                    // what makes that retry happen.
                    tonic::Status::unavailable(format!(
                        "the stream reset was recorded but its requeue failed: {error}"
                    ))
                })?;
                if requeued > RESET_REQUEUE_LOG_THRESHOLD {
                    warn!(
                        cell_id = %self.cell_id,
                        requeued,
                        "an epoch reset requeued an unusually large retained backlog"
                    );
                }
                self.note_success(&principal);
                metrics::record_reset_report(metrics::RESET_ACCEPTED);
                info!(
                    cell_id = %self.cell_id,
                    reset_generation = stored.reset_generation,
                    requeued,
                    "stream reset fence installed and retained unsafe rows requeued"
                );
                Ok(tonic::Response::new(StoredAck(stored.ack_bytes)))
            }
            ResetAcceptance::DetectionMismatch => {
                self.note_rejection(&principal, metrics::RESET_DETECTION_MISMATCH, || {
                    "rejected a stream reset report whose detection did not match its stored \
                     record"
                        .to_owned()
                });
                Err(ResetReportErrorV1::ResetDetectionMismatch.status())
            }
            ResetAcceptance::PlacementMismatch { .. } => {
                self.note_rejection(&principal, metrics::RESET_PLACEMENT_MISMATCH, || {
                    "rejected a stream reset report against a placement this cell does not hold"
                        .to_owned()
                });
                Err(ResetReportErrorV1::PlacementMismatch.status())
            }
            ResetAcceptance::StaleOldStream { .. } => {
                self.note_rejection(&principal, metrics::RESET_STALE_OLD_STREAM, || {
                    "rejected a stream reset report naming an old stream this cell has moved past"
                        .to_owned()
                });
                Err(ResetReportErrorV1::StaleOldStream.status())
            }
            ResetAcceptance::InvalidSuccessor { rule } => {
                self.note_rejection(&principal, metrics::RESET_INVALID_SUCCESSOR, || {
                    format!("rejected a stream reset report with an invalid successor: {rule}")
                });
                Err(ResetReportErrorV1::InvalidSuccessorStream.status())
            }
            ResetAcceptance::CellUnknown => {
                self.note_rejection(&principal, metrics::RESET_CELL_UNKNOWN, || {
                    "rejected a stream reset report on a cell with no outbox membership state"
                        .to_owned()
                });
                // The cell has no membership state, so it has never been through
                // cutover and holds no outbox rows a reset could void. Reported
                // as a precondition rather than as a mismatch: nothing about the
                // report is wrong.
                Err(tonic::Status::new(
                    ResetReportErrorV1::StaleOldStream.code(),
                    format!(
                        "{}: this cell has no outbox membership state, so it has not completed \
                         cutover",
                        ResetReportErrorV1::StaleOldStream.detail()
                    ),
                ))
            }
        }
    }
}

#[async_trait]
impl StreamResetService for StreamResetHandler {
    async fn report_stream_reset(
        &self,
        request: tonic::Request<StreamResetReportV1>,
    ) -> Result<tonic::Response<StoredAck>, tonic::Status> {
        self.serve(request).await
    }
}

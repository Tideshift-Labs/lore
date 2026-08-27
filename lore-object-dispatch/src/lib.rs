// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Dark, server-only object-store dispatch authority primitives.
//!
//! This crate is not wired into loreserver composition. Its source cannot authorize provider
//! traffic or first-seen admission until the WP-121 deployment and calibration gates are current.

pub mod auth;
pub mod authority;
pub mod config;
pub mod continuity;
pub mod metrics;
pub mod request;
pub mod schema;
pub mod server;
pub mod service;
pub mod spool;

pub use auth::AuthenticatedCaller;
pub use auth::AuthorizedCallerEntry;
pub use auth::AuthorizedCallerRegistry;
pub use auth::CallerAuthenticationError;
pub use auth::CallerRegistryError;
pub use authority::AuthenticatedRequestContext;
pub use authority::AuthorityValidationError;
pub use authority::CellAllocationState;
pub use authority::CurrentCellAdmission;
pub use authority::CurrentCellAllocation;
pub use authority::SubmittedAuthority;
pub use authority::validate_request_authority;
pub use config::SERVICE_CONFIG_REVISION;
pub use config::ServiceConfig;
pub use config::ServiceConfigError;
pub use metrics::DispatchMetricRecorder;
pub use metrics::DispatchMetrics;
pub use metrics::DispatchRpc;
pub use request::AuthenticatedConsumerIdentity;
pub use request::DurablePutSpoolExpectation;
pub use request::DurableRequestKey;
pub use request::ExistingFingerprint;
pub use request::ExpectedCellAdmission;
pub use request::ExpectedRequestAuthority;
pub use request::FirstSeenIdentityDecision;
pub use request::FirstSeenPrerequisites;
pub use request::IdempotencyDecision;
pub use request::ObjectStoreOperationLimits;
pub use request::RequestContractError;
pub use request::RequestFingerprintLimits;
pub use request::RequestIdentityLimits;
pub use request::ReservationPolicyLimits;
pub use request::ReservationRequirement;
pub use request::ValidatedRequest;
pub use request::classify_first_seen_identity;
pub use request::classify_idempotency;
pub use request::fingerprint_object_store_request;
pub use request::validate_first_seen_prerequisites;
pub use request::validate_submitted_request_fingerprint;
pub use server::MAX_TLS_PEM_BYTES;
pub use server::ServiceServerError;
pub use server::ServiceTlsConfig;
pub use server::ServiceTlsConfigError;
pub use server::serve;
pub use server::serve_prebound_with_tls;
pub use server::serve_with_registry;
pub use service::SOURCE_DARK_STATUS_MESSAGE;
pub use service::SourceDarkObjectStoreDispatchService;
pub use spool::LedgerSpoolView;
pub use spool::SPOOL_LAYOUT_REVISION_V1;
pub use spool::SpoolBoundaryBinding;
pub use spool::SpoolLayout;
pub use spool::SpoolLayoutError;
pub use spool::SpoolObjectKey;
pub use spool::SpoolObjectKind;
pub use spool::SpoolPaths;
pub use spool::SpoolRecoveryDecision;
pub use spool::SpoolRecoveryInconsistency;
pub use spool::VerifiedFileObservation;
pub use spool::classify_spool_recovery;
pub use spool::validate_spool_boundary_binding;

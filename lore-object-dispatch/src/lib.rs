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
pub mod schema;
pub mod server;
pub mod service;

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
pub use server::MAX_TLS_PEM_BYTES;
pub use server::ServiceServerError;
pub use server::ServiceTlsConfig;
pub use server::ServiceTlsConfigError;
pub use server::serve;
pub use server::serve_prebound_with_tls;
pub use server::serve_with_registry;
pub use service::SOURCE_DARK_STATUS_MESSAGE;
pub use service::SourceDarkObjectStoreDispatchService;

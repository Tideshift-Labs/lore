// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Support for WP-109 Phase 3: two real loreserver **processes** over one cell
//! Postgres database and one MinIO bucket.
//!
//! # What makes this different from the Phase 2 harness
//!
//! Phase 2 (`lore-postgres/tests/active_active_shared_backend.rs`) opens two
//! independently constructed coordinator/store sets inside one test process.
//! That proves the store and coordinator layers, and it cannot prove anything
//! about a *process*: no server composition runs, no relay worker loop exists,
//! no readiness surface is served, and a `kill` is a dropped `Arc` rather than
//! a `SIGKILL` between a COMMIT and the claim that was going to follow it.
//!
//! This module starts the real `loreserver` binary twice, on distinct ports and
//! distinct state directories, against the same database and the same bucket,
//! and drives it over real gRPC.
//!
//! # The three roles the harness plays, and why they are different
//!
//! 1. **Client.** Repository create, branch push, lock, and read RPCs go over
//!    gRPC to one of the two processes, with a real bearer token this harness
//!    mints and both processes verify against a real JWKS endpoint. Nothing is
//!    faked on this path.
//! 2. **Content fixture.** Revision *content* is written straight into the
//!    shared backend through `lore-postgres`' own stores, the same way a server
//!    would, because a revision must already exist in the immutable store
//!    before `BranchPush` will accept it (`verify_fragments`), and the shortest
//!    honest way to put one there is to write it. This is a fixture, not a
//!    client action, and the report says so.
//! 3. **Authority.** Every assertion about what actually happened reads the
//!    database over a THIRD connection this harness owns, never through either
//!    server. A server's own answer about its own write is not authority.
//!
//! # Two arming modes, because no single cell can run both paths today
//!
//! A governed branch push — the only mutation that appends an outbox row — is
//! refused unless the cell has a fenced lock coordinator: `push_governance`
//! calls `reject_unwired_governed_operation` when `domain.lock_coordinator()`
//! is `None` (`lore-server/src/grpc/handlers/branch_push.rs:399-407`). But
//! arming fenced routing makes the **public** lock mutation RPCs refuse
//! outright, by design, until WP-120's public mutation contract exists
//! (`lore-server/src/grpc/lock_service.rs:291,460,539`, guarded by
//! `schema::PUBLIC_MUTATION_CONTRACT_AVAILABLE`).
//!
//! So a cell can prove cross-process lock ownership through the public service,
//! or it can prove the governed outbox path, but not both. [`Arming`] is that
//! choice, made per case, and the runner gives every case its own database so
//! the two never share a cell.

#![allow(dead_code)]

pub mod backend;
pub mod carriage;
pub mod cell;
pub mod client;
pub mod jwks;

use std::path::PathBuf;

/// Which coordination path this case's cell is armed for.
///
/// Not a knob: the two are mutually exclusive in the current tree and the
/// reason is recorded in this module's documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arming {
    /// Fenced lock routing armed. Governed pushes work and append outbox rows;
    /// the public lock mutation RPCs refuse.
    GovernedOutbox,
    /// Fenced routing not armed. The public lock service serves acquire and
    /// release against the shared store; a governed push would be refused.
    PublicLocks,
}

/// The environment contract between the PowerShell runner and these tests.
///
/// Every field is required. A missing one panics with a message naming the
/// variable, because WP-109 is explicit that a body which skipped its setup is
/// `NOT RUN` and can never be counted as evidence — and the runner is the thing
/// that is supposed to have supplied it.
#[derive(Debug, Clone)]
pub struct Env {
    /// Per-case disposable database on the shared cell Postgres.
    pub pg_url: String,
    /// Release `loreserver` binary both processes are started from.
    pub server_bin: PathBuf,
    /// Per-case MinIO bucket. Pre-created by the runner: loreserver HEADs its
    /// bucket at boot and never creates one.
    pub s3_bucket: String,
    pub s3_endpoint: String,
    pub s3_region: String,
    pub s3_access_key: String,
    pub s3_secret_key: String,
    /// The JWKS document this harness serves and both processes fetch.
    pub jwks_json: PathBuf,
    /// The private half, used to mint the tokens that document accepts.
    pub jwt_private_key: PathBuf,
    pub jwt_kid: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    /// Private gateway both relays publish to, and its mTLS material.
    pub gateway_uri: String,
    pub cell_id: String,
    pub placement_epoch: i64,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub trust_roots: PathBuf,
    /// Per-case scratch root for config and state directories.
    pub work_dir: PathBuf,
    /// First of the five loopback ports this case owns.
    pub port_base: u16,
}

fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "{name} is not set. This case is NOT RUN, not failed: run it through \
             tests/run-active-active-two-process-live.ps1, which provisions the database, \
             bucket, gateway, and certificates and exports the whole contract."
        ),
    }
}

impl Env {
    /// Read the contract, or panic naming the first variable that is absent.
    pub fn from_process() -> Self {
        let port_base: u16 = required("LORE_AA2P_PORT_BASE")
            .parse()
            .expect("LORE_AA2P_PORT_BASE must be a u16");
        Self {
            pg_url: required("LORE_TEST_PG_URL"),
            server_bin: PathBuf::from(required("LORE_AA2P_SERVER_BIN")),
            s3_bucket: required("LORE_AA2P_S3_BUCKET"),
            s3_endpoint: required("LORE_AA2P_S3_ENDPOINT"),
            s3_region: required("LORE_AA2P_S3_REGION"),
            s3_access_key: required("LORE_AA2P_S3_ACCESS_KEY"),
            s3_secret_key: required("LORE_AA2P_S3_SECRET_KEY"),
            jwks_json: PathBuf::from(required("LORE_AA2P_JWKS_JSON")),
            jwt_private_key: PathBuf::from(required("LORE_AA2P_JWT_PRIVATE_KEY")),
            jwt_kid: required("LORE_AA2P_JWT_KID"),
            jwt_issuer: required("LORE_AA2P_JWT_ISSUER"),
            jwt_audience: required("LORE_AA2P_JWT_AUDIENCE"),
            gateway_uri: required("LORE_AA2P_GATEWAY_URI"),
            cell_id: required("LORE_AA2P_CELL_ID"),
            placement_epoch: required("LORE_AA2P_PLACEMENT_EPOCH")
                .parse()
                .expect("LORE_AA2P_PLACEMENT_EPOCH must be an i64"),
            client_cert: PathBuf::from(required("LORE_AA2P_CLIENT_CERT")),
            client_key: PathBuf::from(required("LORE_AA2P_CLIENT_KEY")),
            trust_roots: PathBuf::from(required("LORE_AA2P_TRUST_ROOTS")),
            work_dir: PathBuf::from(required("LORE_AA2P_WORK_DIR")),
            port_base,
        }
    }

    /// Port the harness serves its JWKS document on.
    pub fn jwks_port(&self) -> u16 {
        self.port_base
    }
    /// Process A's gRPC and HTTP ports.
    pub fn a_ports(&self) -> (u16, u16) {
        (self.port_base + 1, self.port_base + 2)
    }
    /// Process B's gRPC and HTTP ports.
    pub fn b_ports(&self) -> (u16, u16) {
        (self.port_base + 3, self.port_base + 4)
    }
    /// The URL both processes fetch keys from.
    pub fn jwks_url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/.well-known/jwks.json",
            self.jwks_port()
        )
    }
}

/// A TOML-safe rendering of a filesystem path.
///
/// Backslashes are TOML escape characters, so a Windows path pasted into a
/// basic string silently corrupts. Forward slashes are accepted by every
/// consumer here.
pub fn toml_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "/")
}

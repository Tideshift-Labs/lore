// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Consolidated FFI error types for the Lore system.
//!
//! All discrete error types with FFI codes are defined here,
//! providing a single source of truth for FFI error code allocation.
//! This is the base error crate with no dependency on lore-storage.
//!
//! # Code allocation
//!
//! Codes are grouped into blocks by the kind of failure they report, so a
//! consumer can branch on a range when it only cares about the category and on
//! the exact value when it cares about the specific error.
//!
//! Every code is also a process exit status: the CLI returns the failing
//! error's code from `main` as `ExitCode::from(code as u8)`. That fixes two
//! things. Every code must fit in a `u8`, and no code may land on a value the
//! shell or the OS already spends on something else — a `lore` command that
//! exited 130 would be indistinguishable from one the user killed with Ctrl-C.
//! The reserved rows below are those values, and no group block overlaps one.
//!
//! | Range | Group | Meaning |
//! | --- | --- | --- |
//! | 0 | *reserved* | Success. |
//! | 1 | *reserved* | The CLI's own general failure (`ExitCode::FAILURE`), and the shell's generic error. |
//! | 2 | *reserved* | The CLI's usage exit, and the shell's "misuse of a builtin". |
//! | 3–15 | Input and validation | The request itself was malformed or names the wrong kind of thing. |
//! | 16–27 | Authentication and authorization | The caller is not known, or is known and not permitted. |
//! | 28–39 | Connectivity and availability | The remote could not be reached or is not currently serving. |
//! | 40–55 | Repository state | The repository is in a state that refuses the operation. |
//! | 56–63 | Already exists | Creating a resource that is already there. |
//! | 64–78 | *reserved* | The BSD `sysexits.h` codes (`EX_USAGE` through `EX_CONFIG`). |
//! | 79–99 | Not found | A named resource does not exist. |
//! | 100–109 | *reserved* | The legacy `LoreError` categories (101, 102, 103). |
//! | 110–117 | Configuration | Something the operation needs was never configured. |
//! | 118–125 | Resource limits | A size, depth, or efficiency bound was hit. |
//! | 126–128 | *reserved* | The shell's "found but not executable", "not found", and "bad argument to exit". |
//! | 129–192 | *reserved* | `128 + signal`, i.e. killed by a signal. 130 is Ctrl-C, 137 is `SIGKILL`, 143 is `SIGTERM`. |
//! | 193–200 | Library lifecycle | The library cannot serve the call. |
//! | 201–247 | *reserved* | Free for future groups. |
//! | 248–254 | Outcome (FORK-LOCAL, Tideshift) | The request was dispatched and what it did is not known. |
//! | 255 | *reserved* | `Internal`, which is `-1` truncated to a `u8`. |
//!
//! FORK-LOCAL (Tideshift, WP-120): the Outcome block is not an upstream group. It sits at the
//! TOP of the free range on purpose. Upstream allocates new groups from the bottom of the free
//! range, so a fork group at the top stays clear of every future upstream allocation. It was
//! first allocated at 193–199 and moved to 248–254 when upstream v0.10.0 took 193–200 for
//! `ShutDown`.
//!
//! The trait carries a code as `i32` rather than a `u8` because `Internal` is
//! `-1`, which is not a code allocated here.
//!
//! Add a new error to the block that matches its group and take the next free
//! code in that block. Never renumber an existing code to close a gap: the gaps
//! are the headroom that keeps a group contiguous, and the tests below hold
//! every block clear of the reserved values so anything taken from that
//! headroom is a usable exit status. New groups come out of 201–247; 248–254 is the fork's Outcome block. A type
//! whose name ends in `NotFound` belongs in the not-found block even when it
//! also belongs to a subsystem that has its own errors elsewhere —
//! `PluginNotFound` sits with the other not-found codes, not with the other
//! plugin codes.

use std::fmt;

use lore_error_set::FfiError;
use thiserror::Error;

/// Scopes `#[ffi_code(N)]` to this module.
///
/// `#[derive(FfiError)]` expands to a reference to this name, resolved where
/// the derive is written rather than in the macro crate. Declaring it here and
/// nowhere else means a code allocated outside this registry does not compile,
/// which is what keeps the allocation table below the single source of truth.
fn __ffi_code_registry_marker() {}

// ---------------------------------------------------------------------------
// Input and validation (3–15)
//
// The arguments the caller supplied cannot be acted on: they are malformed,
// they name the wrong kind of thing, or they ask for something the library
// does not implement.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error, FfiError)]
#[error("invalid arguments: {reason}")]
#[ffi_code(3)]
pub struct InvalidArguments {
    pub reason: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("invalid path: {path}")]
#[ffi_code(4)]
pub struct InvalidPath {
    pub path: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("invalid address: {address}")]
#[ffi_code(5)]
pub struct InvalidAddress {
    pub address: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Path is not a link: {path}")]
#[ffi_code(6)]
pub struct NotALink {
    pub path: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Path is not a layer: {path}")]
#[ffi_code(7)]
pub struct NotALayer {
    pub path: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Node {node} has parent {actual_parent} but was reached as a child of {expected_parent}")]
#[ffi_code(8)]
pub struct InvalidNodeHierarchy {
    pub node: u32,
    pub expected_parent: u32,
    pub actual_parent: u32,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Operation not supported: {operation}")]
#[ffi_code(9)]
pub struct NotSupported {
    pub operation: String,
}

// ---------------------------------------------------------------------------
// Authentication and authorization (16–27)
//
// The caller's identity is missing, unusable, or insufficient for the
// operation.
// ---------------------------------------------------------------------------

/// What a refusal reads as when the deciding party named no reason.
///
/// Deliberately not an empty string. The reason renders after a colon, and an
/// empty one leaves a dangling `Not authenticated: ` that reads as a bug in the
/// client rather than as a server that said nothing.
pub const UNSTATED_REFUSAL: &str = "the server stated no reason";

/// The caller's identity is missing, unusable, or was refused.
///
/// FORK-LOCAL (Tideshift): `reason` carries the deciding party's own words —
/// usually a server's gRPC status message, threaded through
/// `lore-transport`'s status mapping. It exists because the fixed-message unit
/// struct this replaced silently discarded that text: an enforcing cell
/// refusing a push for a precise, actionable cause reached the operator as
/// three characterless words, which cost a full diagnosis session on WP-120.
///
/// The detail crosses the C boundary in the existing `LoreErrorDetail.message`
/// field, which is this type's `Display`. The FFI code stays 16 and no header
/// shape changes, so a consumer that only branches on the code is unaffected.
/// A consumer that shows the message now sees the cause.
///
/// The field follows the sibling precedent in this same registry —
/// `NotConnected { reason }`, `Oversized { context }`, `NotSupported
/// { operation }` — rather than inventing a shape.
#[derive(Debug, Clone, Error, FfiError)]
#[error("Not authenticated: {reason}")]
#[ffi_code(16)]
pub struct NotAuthenticated {
    /// Why the caller is not authenticated, in the deciding party's words.
    ///
    /// Never empty in practice: a construction site with nothing to say uses
    /// [`UNSTATED_REFUSAL`] rather than the empty string.
    pub reason: String,
}

impl NotAuthenticated {
    /// Build the error with a reason. The ergonomic spelling for the many call
    /// sites that hold a `&str` literal.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Not authorized to access repository")]
#[ffi_code(17)]
pub struct NotAuthorized;

#[derive(Debug, Clone, Error, FfiError)]
#[error("No token stored")]
#[ffi_code(18)]
pub struct TokenNotFound;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Operation requires write access")]
#[ffi_code(19)]
pub struct WriteRequired;

// ---------------------------------------------------------------------------
// Connectivity and availability (28–39)
//
// Something the operation had to talk to could not be reached, dropped the
// connection, or is reachable but declining work. Usually the remote; also the
// local service process, which a call is relayed through and which the caller
// reaches the same way — over a connection that may not be there. Retrying
// later is often the right response.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error, FfiError)]
#[error("Disconnected from server")]
#[ffi_code(28)]
pub struct Disconnected;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Not connected to remote: {reason}")]
#[ffi_code(29)]
pub struct NotConnected {
    pub reason: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Server is in maintenance mode")]
#[ffi_code(30)]
pub struct Maintenance;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Store overloaded, slow down")]
#[ffi_code(31)]
pub struct SlowDown;

/// No Lore service could be reached, and none could be started.
///
/// Distinct from [`NotConnected`], which reports a remote: a caller that relays
/// its calls through the local service handles this differently, because it is
/// the one failure that means the operation did not run at all rather than ran
/// and failed. Running the operation in this process instead is a reasonable
/// answer to it and not to any other error here.
#[derive(Debug, Clone, Error, FfiError)]
#[error("Lore service unavailable: {reason}")]
#[ffi_code(32)]
pub struct ServiceUnavailable {
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Repository state (40–55)
//
// The request is well-formed and permitted, but the repository is in a state
// that refuses it: nothing to do, history has moved on, or a rule protects the
// target.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error, FfiError)]
#[error("Nothing staged for commit")]
#[ffi_code(40)]
pub struct NothingStaged;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Branch has been advanced by another instance, sync and re-stage to commit")]
#[ffi_code(41)]
pub struct BranchAdvanced;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Branch history is divergent")]
#[ffi_code(42)]
pub struct Divergent;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Unable to commit when {path} is still in conflict")]
#[ffi_code(43)]
pub struct Conflict {
    pub path: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Local modifications prevent synchronization")]
#[ffi_code(44)]
pub struct LocalModifications;

#[derive(Debug, Clone, Error, FfiError)]
#[error("resource locked by somebody else")]
#[ffi_code(45)]
pub struct LockNotOwned;

#[derive(Debug, Clone, Error, FfiError)]
#[error("New metadata was identical to original")]
#[ffi_code(46)]
pub struct IdenticalMetadata;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Unable to delete a protected branch: {branch}")]
#[ffi_code(47)]
pub struct DeleteProtected {
    pub branch: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Cannot delete the current branch: {branch}")]
#[ffi_code(48)]
pub struct DeleteCurrent {
    pub branch: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Unable to delete default branch: {branch}")]
#[ffi_code(49)]
pub struct DeleteDefault {
    pub branch: String,
}

// ---------------------------------------------------------------------------
// Already exists (56–63)
//
// The operation would create something that is already there.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error, FfiError)]
#[error("Target repository is already used in a layer")]
#[ffi_code(56)]
pub struct AlreadyLinked;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Branch {branch} already exists, use switch instead")]
#[ffi_code(57)]
pub struct BranchAlreadyExists {
    pub branch: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Repository already exist in path {path}")]
#[ffi_code(58)]
pub struct RepositoryAlreadyExists {
    pub path: String,
}

// ---------------------------------------------------------------------------
// Not found (79–99)
//
// A resource the operation named does not exist. The generic `NotFound` leads
// the block; the rest are ordered from content-addressed storage outwards to
// repository-level objects. The block starts at 79 because 64–78 belong to the
// BSD `sysexits.h` conventions.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error, FfiError)]
#[error("Not found")]
#[ffi_code(79)]
pub struct NotFound;

#[derive(Clone, Error, FfiError)]
#[error("Address not found: {}", AddressNotFound::format_address(&self.address))]
#[ffi_code(80)]
pub struct AddressNotFound {
    /// Raw 48-byte address (32-byte hash + 16-byte context)
    pub address: [u8; 48],
}

impl AddressNotFound {
    fn format_address(address: &[u8; 48]) -> String {
        format!(
            "{}-{}",
            hex::encode(&address[..32]),
            hex::encode(&address[32..])
        )
    }
}

impl fmt::Debug for AddressNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AddressNotFound({})",
            Self::format_address(&self.address)
        )
    }
}

#[derive(Clone, Error, FfiError)]
#[error("Payload not found: {}", hex::encode(self.hash))]
#[ffi_code(81)]
pub struct PayloadNotFound {
    /// Raw 32-byte hash
    pub hash: [u8; 32],
}

impl fmt::Debug for PayloadNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PayloadNotFound({})", hex::encode(self.hash))
    }
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("file not found: {resource}")]
#[ffi_code(82)]
pub struct FileNotFound {
    pub resource: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Node not found")]
#[ffi_code(83)]
pub struct NodeNotFound;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Link not found")]
#[ffi_code(84)]
pub struct LinkNotFound;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Link not found at path: {path}")]
#[ffi_code(85)]
pub struct LinkPathNotFound {
    pub path: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Layer not found")]
#[ffi_code(86)]
pub struct LayerNotFound;

#[derive(Debug, Clone, Error, FfiError)]
#[error("branch not found: {branch}")]
#[ffi_code(87)]
pub struct BranchNotFound {
    pub branch: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("revision not found: {revision}")]
#[ffi_code(88)]
pub struct RevisionNotFound {
    pub revision: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Repository not found: {repository}")]
#[ffi_code(89)]
pub struct RepositoryNotFound {
    pub repository: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("A shared store was supposed to exist at {path}")]
#[ffi_code(90)]
pub struct SharedStoreNotFound {
    pub path: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("lock does not exist")]
#[ffi_code(91)]
pub struct LockNotFound;

#[derive(Debug, Clone, Error, FfiError)]
#[error(
    "Plugin '{plugin_name}' not found. Available plugins: {}",
    format_available_plugins(available_plugins)
)]
#[ffi_code(92)]
pub struct PluginNotFound {
    pub plugin_name: String,
    pub available_plugins: Vec<String>,
}

fn format_available_plugins(plugins: &[String]) -> String {
    if plugins.is_empty() {
        "none".to_string()
    } else {
        plugins.join(", ")
    }
}

// ---------------------------------------------------------------------------
// Configuration (110–117)
//
// Something the operation needs was never configured, or was configured in a
// way that will not load. The block starts at 110 because 100–109 is reserved
// for the legacy `LoreError` categories, which share this numeric space.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error, FfiError)]
#[error("No commit identity configured; pass --identity or set identity in .lore/config.toml")]
#[ffi_code(110)]
pub struct MissingIdentity;

#[derive(Debug, Clone, Error, FfiError)]
#[error("No remote configured")]
#[ffi_code(111)]
pub struct NoRemote;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Plugin '{plugin_name}' configuration error: {message}")]
#[ffi_code(112)]
pub struct PluginConfigError {
    pub plugin_name: String,
    pub message: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Plugin '{plugin_name}' initialization failed: {message}")]
#[ffi_code(113)]
pub struct PluginInitError {
    pub plugin_name: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Resource limits (118–125)
//
// A size, depth, or efficiency bound was reached. The operation was refused on
// the bound, not on anything wrong with the request. This is the last block
// below 126, where the shell's own exit statuses begin.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error, FfiError)]
#[error("Oversized: {context}")]
#[ffi_code(118)]
pub struct Oversized {
    pub context: String,
}

#[derive(Debug, Clone, Error, FfiError)]
#[error("Branch history has reached maximum search depth")]
#[ffi_code(119)]
pub struct MaxHistorySearchDepth;

#[derive(Debug, Clone, Error, FfiError)]
#[error("Compression would be inefficient")]
#[ffi_code(120)]
pub struct InefficientCompression;

// ---------------------------------------------------------------------------
// Library lifecycle (193–200)
//
// The library itself cannot serve the call. The error is caused by the
// library's own state rather than the request, the caller's identity, or
// anything a remote did.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Error, FfiError)]
#[error("Lore has been shut down")]
#[ffi_code(193)]
pub struct ShutDown;

// ---------------------------------------------------------------------------
// Outcome (248–254) — FORK-LOCAL (Tideshift, WP-120)
//
// The request reached the server and what it did is not known. This is not a
// failure and not a success, and it is emphatically not a connectivity error:
// the whole point of giving it its own group is that the ordinary "retry
// later" reading of the 28–39 block is the one response that must never be
// applied to it.
//
// The block comes out of the free headroom rather than out of an existing
// group because no existing group's meaning is true of it. It takes the TOP of
// that headroom because upstream allocates its new groups from the bottom. A caller branching
// on the range learns "the outcome is unresolved", which is the only thing it
// may act on until an operation-specific authoritative read says more.
// ---------------------------------------------------------------------------

/// A mutable request was dispatched and no decisive answer came back.
///
/// The server may or may not have applied it. Nothing in this error says which,
/// and nothing later may infer it from current state: a subsequent read reports
/// where the repository is now, not what this attempt did.
///
/// `attempt_id` is minted before the request is dispatched, so it names the
/// attempt whose outcome is unresolved rather than the moment the loss was
/// noticed. A caller carries it into its own durable record and quotes it to
/// whatever authoritative receipt lookup can eventually resolve the attempt.
/// It is deliberately a `String` rather than a typed id: this crate sits below
/// every transport that mints one, and the value crosses the FFI boundary as
/// text either way.
#[derive(Debug, Clone, Error, FfiError)]
#[error(
    "{operation}: dispatched, response lost, outcome unknown (attempt {attempt_id}); read authoritative state before any new attempt"
)]
#[ffi_code(248)]
// Publishes the two fields through `FfiError::outcome_identity`, so a consumer across the C
// boundary reads them as data rather than parsing them back out of the message above. This is
// the only error in the registry that names an attempt, and the only one that needs to: the
// caller's next move after this error is to look that exact attempt up.
#[ffi_outcome_identity(operation, attempt_id)]
pub struct OutcomeUnknown {
    /// The operation whose response was lost, named as the wire names it.
    pub operation: String,
    /// The identity the attempt was dispatched under.
    pub attempt_id: String,
}

/// The server granted a resource this call cannot name, so it cannot undo it.
///
/// Allocated from this block rather than from a failure group because the range's
/// meaning is exactly right: the caller learns the outcome is unresolved. A lock
/// is held, the operation did not succeed, and the client has no path to release
/// it with — reporting a decisive failure would say the request is over and
/// nothing is outstanding, which is the one reading this block exists to prevent.
///
/// It carries NO attempt identity, and that is the difference from
/// [`OutcomeUnknown`] rather than an omission. There is nothing to look up: the
/// resource was granted by a batch that answered, so its attempt resolved, and
/// what is unresolved is the client's ability to name the row at all. An
/// `attempt_id` here would send a reconciler to a receipt that settles nothing.
/// `resource` is what a human needs instead, in whatever terms the server used.
#[derive(Debug, Clone, Error, FfiError)]
#[error(
    "granted a resource this call cannot name and cannot release ({resource}); release it by name or ask an administrator"
)]
#[ffi_code(249)]
pub struct UnnameableResource {
    /// The resource as the server described it, which is all the caller has.
    pub resource: String,
}

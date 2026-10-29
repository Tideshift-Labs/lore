// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The crate's tests that can share a process, as one integration-test binary.
//!
//! They link the library as an ordinary dependency instead of compiling it a
//! second time in test mode. A test that needs a process of its own goes in a
//! separate `tests/*.rs` file instead.

mod attempt_store;
mod auth;
mod caller_operation;
mod connection;
mod error;
mod grpc;
mod outcome;
mod quic;
mod session;
mod session_pool;
mod types;
mod unmanaged_write;

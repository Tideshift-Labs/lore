// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Dark, server-only object-store dispatch authority primitives.
//!
//! This crate is not wired into loreserver composition. Its source cannot authorize provider
//! traffic or first-seen admission until the WP-121 deployment and calibration gates are current.

pub mod continuity;

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Postgres store implementations (CR-007).
//!
//! The coordinated fragment route has a seam-owned construction and cell
//! attestation path. `lore-server` activates it only for a complete, explicitly
//! enabled `fragment_provider` configuration after lifecycle readiness and the
//! process-wide connection budget have both passed; absent and disabled
//! configurations retain the legacy route.

mod fragment_transport;
pub mod immutable_store;
pub mod lock_store;
pub mod mutable_store;

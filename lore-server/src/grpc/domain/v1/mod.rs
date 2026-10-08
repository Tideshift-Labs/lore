// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

#[cfg(feature = "test-util")]
pub mod service;
#[cfg(not(feature = "test-util"))]
mod service;
#[cfg(feature = "test-util")]
pub mod strict_codec;
#[cfg(not(feature = "test-util"))]
mod strict_codec;

pub use service::LoreDomainOperationV1Service;

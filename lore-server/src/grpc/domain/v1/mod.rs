// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

mod service;
mod strict_codec;

pub use service::LoreDomainOperationV1Service;

#[cfg(test)]
mod tests;

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::BoundProviderAttemptAudit;

fn main() {
    // Every field is private and there is no public constructor other than
    // `ProviderAttemptLedger::audit_for`, so this struct-literal is rejected at compile time
    // regardless of what the private fields are named -- the compile-fail assertion is that this
    // has no fields an external crate can supply.
    let _ = BoundProviderAttemptAudit {};
}

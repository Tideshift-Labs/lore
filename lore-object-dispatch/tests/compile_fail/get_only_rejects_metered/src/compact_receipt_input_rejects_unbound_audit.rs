// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::ObjectStoreCompactReceiptInput;
use lore_object_dispatch::ObjectStoreProviderAttemptAudit;

fn main() {
    let audit = ObjectStoreProviderAttemptAudit {
        attempt_count: 0,
        committed_grant_count: 0,
        no_dispatch_count: 0,
        decisive_terminal_count: 0,
        ambiguous_count: 0,
        provider_authority_refunded: false,
        audit_blake3: None,
    };
    // `ObjectStoreCompactReceiptInput::provider_attempt_audit` requires a `BoundProviderAttemptAudit`
    // (WP-114 CD-8), so a bare `ObjectStoreProviderAttemptAudit` -- constructible as a plain struct
    // literal by any caller -- must not type-check here.
    let _ = ObjectStoreCompactReceiptInput {
        provider_attempt_audit: &audit,
        ..todo!("the compile-fail assertion is the mismatched audit type")
    };
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::ProviderAttemptClass;
use lore_object_dispatch::ProviderDirectPutAttemptRequest;

fn main() {
    let _ = ProviderDirectPutAttemptRequest {
        attempt_class: ProviderAttemptClass::HeadObject,
        ..todo!("the compile-fail assertion is the unknown operation-class field")
    };
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_fragment_provider::AdmittedFragmentAttempt;

async fn general_token_cannot_send_put(token: AdmittedFragmentAttempt<'_>) {
    let _ = token.execute_direct_put(todo!(), todo!()).await;
}

fn main() {}

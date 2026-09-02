// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_fragment_provider::FragmentProviderGateway;

async fn cannot_send_before_admission(gateway: &FragmentProviderGateway) {
    let _ = gateway.execute_direct_put(todo!(), todo!()).await;
}

fn main() {}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::GovernedProviderClient;
use lore_object_dispatch::MeteredProviderAttemptRequest;
use lore_object_dispatch::ProviderGetTransport;

async fn cannot_widen_get<C, T>(
    client: &GovernedProviderClient<C, T>,
    metered: &MeteredProviderAttemptRequest,
) where
    T: ProviderGetTransport<Operation = ()>,
{
    let _ = client.execute_get(metered, &()).await;
}

fn main() {}

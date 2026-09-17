// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_fragment_provider::FragmentDrainCapability;

fn cannot_reach_the_pool(capability: &FragmentDrainCapability) {
    let _ = capability.pool();
}

fn cannot_reach_the_dispatch_client(capability: &FragmentDrainCapability) {
    let _ = capability.dispatch();
}

fn cannot_reach_the_gateway(capability: &FragmentDrainCapability) {
    let _ = capability.gateway();
}

fn cannot_reach_the_entry(capability: &FragmentDrainCapability) {
    let _ = capability.entry();
}

fn main() {}

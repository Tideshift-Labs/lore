// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_fragment_provider::FragmentDrainAttempt;

fn cannot_name_a_traffic_class(attempt: &FragmentDrainAttempt) {
    let _ = &attempt.traffic_class;
}

fn cannot_name_an_attempt_class(attempt: &FragmentDrainAttempt) {
    let _ = &attempt.attempt_class;
}

fn cannot_name_a_declared_size(attempt: &FragmentDrainAttempt) {
    let _ = &attempt.declared_size;
}

fn cannot_name_a_declared_blake3(attempt: &FragmentDrainAttempt) {
    let _ = &attempt.declared_blake3;
}

fn cannot_name_a_target(attempt: &FragmentDrainAttempt) {
    let _ = &attempt.target;
}

fn main() {}

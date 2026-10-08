// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_postgres::domain::outbox::EvaluationBlock;
use lore_postgres::domain::outbox::SafetyBlock;
use lore_server::event_relay::evaluator_task::block_label;
use lore_server::event_relay::metrics;

#[test]
fn every_evaluation_block_has_its_own_label() {
    let blocks = [
        EvaluationBlock::CellUnknown,
        EvaluationBlock::MissingCheckpoint {
            receiver_identity: "loreserver-sfo3-cell-a-1".to_string(),
            membership_generation: 4,
        },
        EvaluationBlock::Membership(SafetyBlock::ResetInProgress),
        EvaluationBlock::Membership(SafetyBlock::NoCurrentPlacement),
        EvaluationBlock::Membership(SafetyBlock::EmptyRequiredMembership),
        EvaluationBlock::Membership(SafetyBlock::MemberNotReady {
            receiver_identity: "loreserver-sfo3-cell-a-1".to_string(),
            membership_generation: 4,
            state: "joining".to_string(),
        }),
    ];
    let mut labels: Vec<&'static str> = blocks.iter().map(block_label).collect();
    let total = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(
        labels.len(),
        total,
        "two blocks share a label, so two different operator signals merge"
    );
}

/// A label never carries a receiver identity or a generation. Those are the
/// unbounded values CR-032 prohibits, and both blocked variants carry them.
#[test]
fn no_label_carries_an_identity() {
    let block = EvaluationBlock::MissingCheckpoint {
        receiver_identity: "loreserver-sfo3-cell-a-1".to_string(),
        membership_generation: 4,
    };
    let label = block_label(&block);
    assert!(!label.contains("loreserver"));
    assert!(!label.contains('4'));
    assert_eq!(label, metrics::BLOCK_MISSING_CHECKPOINT);
}

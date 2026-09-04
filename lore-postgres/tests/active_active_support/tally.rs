// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Seeded identities and the winner/loser/unknown/duplicate tally.
//!
//! WP-109 Phase 2 asks for high-contention repetitions with preserved seeds and
//! reported outcome counts. Two halves:
//!
//! - [`Identities`] derives every repository id, branch id, name, content hash,
//!   and cell id in a case from one printed `u64`. Re-running with
//!   `LORE_TEST_SEED` set to that value reproduces the same identities. It does
//!   **not** reproduce the interleaving — nothing here controls scheduling, and
//!   the seed must not be read as if it did.
//! - [`RaceTally`] counts the four outcome classes across rounds and prints
//!   them. `unknown` is a real class here, not padding: a `.settled` failpoint
//!   configured with the `unknown` action turns a committed mutation into
//!   `DomainError::OutcomeUnknown`, and a proof that cannot count those cannot
//!   describe what WP-109 calls a response loss.

#![allow(dead_code)]

/// SplitMix64. Small, dependency-free, and good enough for identity material;
/// nothing here is cryptographic.
pub struct Identities {
    seed: u64,
    state: u64,
}

impl Identities {
    /// Start a stream from `seed` and announce it, so a failing run is
    /// replayable from its own output.
    pub fn from_seed(seed: u64) -> Self {
        println!("case identity seed: {seed}");
        Self { seed, state: seed }
    }

    /// The seed this stream was built from.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            let take = chunk.len();
            chunk.copy_from_slice(&word[..take]);
        }
    }

    /// A 16-byte identity: repository, branch, or fragment context.
    pub fn id16(&mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        self.fill(&mut out);
        out
    }

    /// A 32-byte identity: content hash, metadata pointer, or resource hash.
    pub fn id32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.fill(&mut out);
        out
    }

    /// A repository name unique to this stream position.
    pub fn name(&mut self, label: &str) -> String {
        format!("wp109-{label}-{:016x}", self.next_u64())
    }

    /// A cell identity unique to this stream position.
    pub fn cell_id(&mut self) -> String {
        format!("wp109-cell-{:016x}", self.next_u64())
    }

    /// `len` bytes of payload content, so two sets can be handed byte-identical
    /// or deliberately different content from one seeded stream.
    pub fn content(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.fill(&mut out);
        out
    }
}

/// How one participant finished one round of a race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaceOutcome {
    /// This participant's mutation was the one that committed.
    Won,
    /// Decisively refused: a CAS loss, a generation mismatch, a foreign owner,
    /// a fence. A committed outcome, not an error.
    Lost,
    /// The mutation may or may not have committed as far as this caller can
    /// tell. Requires a reconciliation read against authoritative state.
    Unknown,
    /// A second delivery of an outcome already recorded — an idempotent replay
    /// rather than a second effect.
    Duplicate,
}

/// Outcome counts for one race, across however many rounds it ran.
pub struct RaceTally {
    label: String,
    seed: u64,
    rounds: usize,
    won: usize,
    lost: usize,
    unknown: usize,
    duplicate: usize,
}

impl RaceTally {
    /// Open a tally for `label`, carrying the seed its identities came from.
    pub fn new(label: &str, seed: u64) -> Self {
        Self {
            label: label.to_owned(),
            seed,
            rounds: 0,
            won: 0,
            lost: 0,
            unknown: 0,
            duplicate: 0,
        }
    }

    /// Record one round's pair of outcomes and assert the invariant every race
    /// in this harness shares: a round has exactly one winner.
    ///
    /// An `Unknown` counts as a possible win, so a round pairing `Unknown` with
    /// `Lost` is accepted here and must be settled by the case's own
    /// reconciliation read against authoritative SQL. That is the honest
    /// treatment: the caller genuinely does not know, and asserting either way
    /// from the client side would be inventing the answer.
    pub fn round(&mut self, a: RaceOutcome, b: RaceOutcome) {
        self.rounds += 1;
        for outcome in [a, b] {
            match outcome {
                RaceOutcome::Won => self.won += 1,
                RaceOutcome::Lost => self.lost += 1,
                RaceOutcome::Unknown => self.unknown += 1,
                RaceOutcome::Duplicate => self.duplicate += 1,
            }
        }
        let decisive_winners = [a, b]
            .iter()
            .filter(|outcome| **outcome == RaceOutcome::Won)
            .count();
        let unknowns = [a, b]
            .iter()
            .filter(|outcome| **outcome == RaceOutcome::Unknown)
            .count();
        assert!(
            decisive_winners + unknowns >= 1 && decisive_winners <= 1,
            "{}: round {} had {decisive_winners} decisive winner(s) and {unknowns} unknown(s); \
             exactly one participant may commit (seed {})",
            self.label,
            self.rounds,
            self.seed
        );
    }

    /// Print the counts WP-109's evidence section asks for.
    pub fn report(&self) {
        println!(
            "race tally {}: seed={} rounds={} winners={} losers={} unknown={} duplicates={}",
            self.label, self.seed, self.rounds, self.won, self.lost, self.unknown, self.duplicate
        );
    }

    /// Rounds recorded so far.
    pub fn rounds(&self) -> usize {
        self.rounds
    }

    /// Decisive winners recorded so far.
    pub fn winners(&self) -> usize {
        self.won
    }

    /// Decisive losers recorded so far.
    pub fn losers(&self) -> usize {
        self.lost
    }
}

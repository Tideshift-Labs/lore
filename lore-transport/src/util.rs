// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::time::Duration;

pub struct Retry {
    current: u64,
    maximum: u64,
    jitter: f32,
    counter: usize,
    limit: usize,
}

impl Retry {
    pub async fn wait(&mut self) -> bool {
        if self.counter >= self.limit {
            return false;
        }

        // Generate some jitter to avoid alignment storms
        let jitter = rand::random::<f32>() * self.jitter;
        let jitter = std::cmp::min((jitter * self.current as f32) as u64, 100);

        tokio::time::sleep(Duration::from_millis(self.current + jitter)).await;

        self.current = std::cmp::min(self.current * 2, self.maximum);
        self.counter += 1;

        true
    }

    /// The longest the next [`wait`](Self::wait) can sleep, jitter included, or
    /// `None` once the attempt limit is reached.
    ///
    /// Pure: it samples nothing and advances nothing, so a caller may ask
    /// before deciding whether to spend the attempt at all, and asking twice
    /// gives the same answer. That is what makes it usable as a gate in front
    /// of a wall-clock budget — a caller that has to *consume* an attempt to
    /// learn its length cannot refuse one for being too long.
    ///
    /// It is an upper bound rather than the exact figure because `wait`'s
    /// jitter is drawn per call. `rand::random::<f32>()` is strictly below 1.0,
    /// so the sampled jitter is always below the value computed here from the
    /// same expression with the draw at its maximum. A caller comparing this
    /// against a deadline therefore never starts a wait that ends past it.
    pub fn next_delay_upper_bound(&self) -> Option<Duration> {
        if self.counter >= self.limit {
            return None;
        }

        // The same expression `wait` uses, with the random draw at its ceiling.
        let jitter = std::cmp::min((self.jitter * self.current as f32) as u64, 100);
        Some(Duration::from_millis(self.current + jitter))
    }

    pub fn counter(&self) -> usize {
        self.counter
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

const DEFAULT_JITTER: f32 = 0.1;

/// Create a retry waiter, start and maximum times in milliseconds. Will give up
/// after trying for the limit number of times.
pub fn retry(start: u64, maximum: u64, limit: usize) -> Retry {
    Retry {
        current: start,
        maximum,
        jitter: DEFAULT_JITTER,
        counter: 0,
        limit,
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::atomic::AtomicUsize;

pub use lore_base::types::store_types::KeyType;
use serde::Deserialize;
use serde::Serialize;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio_stream::Stream;

use crate::Fragment;
use crate::Hash;

/// Progressive match hierarchy for store lookups.
///
/// When querying the store, callers specify a minimum match level.
/// The store returns the best match found up to the requested level.
///
/// cbindgen:prefix-with-name
/// cbindgen:rename-all=ScreamingSnakeCase
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Eq, Hash, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum StoreMatch {
    #[default]
    MatchNone = 0,
    MatchHash = 1,
    MatchPartition = 2,
    MatchFull = 3,
}

impl StoreMatch {
    pub fn next(&self) -> Option<Self> {
        match self {
            StoreMatch::MatchNone => Some(StoreMatch::MatchHash),
            StoreMatch::MatchHash => Some(StoreMatch::MatchPartition),
            StoreMatch::MatchPartition => Some(StoreMatch::MatchFull),
            StoreMatch::MatchFull => None,
        }
    }

    pub fn prev(&self) -> Option<Self> {
        match self {
            StoreMatch::MatchNone => None,
            StoreMatch::MatchHash => Some(StoreMatch::MatchNone),
            StoreMatch::MatchPartition => Some(StoreMatch::MatchHash),
            StoreMatch::MatchFull => Some(StoreMatch::MatchPartition),
        }
    }

    pub fn is_partial(&self) -> bool {
        self != &StoreMatch::MatchFull
    }
}

impl From<StoreMatch> for u8 {
    fn from(value: StoreMatch) -> Self {
        match value {
            StoreMatch::MatchNone => 0,
            StoreMatch::MatchHash => 1,
            StoreMatch::MatchPartition => 2,
            StoreMatch::MatchFull => 3,
        }
    }
}

impl TryFrom<u8> for StoreMatch {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(StoreMatch::MatchNone),
            1 => Ok(StoreMatch::MatchHash),
            2 => Ok(StoreMatch::MatchPartition),
            3 => Ok(StoreMatch::MatchFull),
            unknown => Err(format!("Unknown store match '{unknown}'")),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct StoreQueryResult {
    pub fragment: Fragment,
    pub match_made: StoreMatch,
}

/// Aggregate stored-fragment accounting for a single repository (partition),
/// as reported by [`ImmutableStore::repository_stats`].
///
/// The figures cover the *distinct fragment hashes associated with the
/// repository*. Under a global (content-addressed) dedup scope a fragment's
/// bytes are stored once and may be referenced by several repositories, so
/// these are the repository's *referenced* footprint: bytes shared with another
/// repository are counted in full for each one, and summing across repositories
/// exceeds the bytes physically held by the store.
///
/// [`ImmutableStore::repository_stats`]: crate::ImmutableStore::repository_stats
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct StoreRepositoryStats {
    /// Number of distinct fragment hashes associated with the repository.
    pub fragment_count: u64,
    /// Sum of the stored (post-encoding) payload sizes of those fragments.
    pub payload_bytes: u64,
    /// Sum of the logical (pre-encoding) content sizes of the same fragments.
    pub content_bytes: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct StoreObliterateStats {
    pub num_fragments: AtomicUsize,
    pub num_payloads: AtomicUsize,
}

pub struct KeyValueStream {
    channel: UnboundedReceiver<(Hash, Hash)>,
}

impl KeyValueStream {
    pub fn new() -> (Self, UnboundedSender<(Hash, Hash)>) {
        // Unbounded to ensure not blocking while holding group bucket read lock
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Self { channel: rx }, tx)
    }

    pub fn channel(self) -> UnboundedReceiver<(Hash, Hash)> {
        self.channel
    }
}

impl Stream for KeyValueStream
where
    Self: Unpin,
{
    type Item = (Hash, Hash);

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.get_mut().channel.poll_recv(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

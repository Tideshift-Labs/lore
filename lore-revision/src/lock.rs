// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use async_trait::async_trait;
use lore_base::types::LockData;
use lore_base::types::LockResource;
use lore_error_set::prelude::*;

use crate::errors::InvalidArguments;
use crate::errors::LockNotFound;
use crate::errors::LockNotOwned;
use crate::errors::SlowDown;
use crate::lore::BranchId;
use crate::lore::Hash;
use crate::lore::RepositoryId;

pub mod file;
pub mod recovered;
pub mod util;

#[error_set]
pub enum LockError {
    InvalidArguments,
    LockNotFound,
    LockNotOwned,
    SlowDown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LockQuery {
    Hash(Hash),
    HashRepository(Hash, RepositoryId),
    HashRepositoryBranch(Hash, RepositoryId, BranchId),
    Owner(String),
    OwnerRepository(String, RepositoryId),
    OwnerRepositoryBranch(String, RepositoryId, BranchId),
    Repository(RepositoryId),
    RepositoryBranch(RepositoryId, BranchId),
    RepositoryBranchDescription(RepositoryId, BranchId, String),
}

#[async_trait]
pub trait LockStore: Send + Sync {
    /// Acquire locks for all of the requested resources. If any resource cannot be locked the
    /// entire operation will fail.
    async fn lock_resources(
        &self,
        owner_id: &str,
        repository: RepositoryId,
        resources: &[LockResource],
    ) -> Result<Vec<LockData>, LockError>;

    /// Query for locks in a variety of ways.
    async fn query_locks(&self, query: LockQuery) -> Result<Vec<LockData>, LockError>;

    /// Check the lock status for the provided resources.
    async fn check_locks_status(
        &self,
        repository: RepositoryId,
        resources: &[LockResource],
    ) -> Result<Vec<LockData>, LockError>;

    /// Unlock all of the requested resources. If any resource cannot be unlocked, the entire
    /// operation will fail.
    async fn unlock_resources(
        &self,
        owner_id: &str,
        validate_user: bool,
        repository: RepositoryId,
        resources: &[LockResource],
    ) -> Result<Vec<LockResource>, LockError>;
}

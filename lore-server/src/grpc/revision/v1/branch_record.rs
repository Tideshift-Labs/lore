// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::types::Hash;
use lore_proto::lore::model::v1 as model_v1;
use lore_revision::branch;
use lore_revision::lore::BranchId;
use lore_revision::metadata::Metadata;
use lore_revision::repository::RepositoryContext;
use tonic::Status;

/// Build a v1 `Branch` response record from already-loaded metadata.
///
/// Callers pass `metadata` + `metadata_hash` they have in scope so the
/// helper fits both pre-load paths (e.g. delete preserves metadata for
/// the deleted response) and post-mutation paths. Missing metadata
/// fields (legacy / partial blobs) fall back to defaults rather than
/// erroring.
pub(super) async fn build_branch(
    repository: Arc<RepositoryContext>,
    branch_id: BranchId,
    metadata: &Metadata,
    metadata_hash: Hash,
    deleted: bool,
) -> Result<model_v1::Branch, Status> {
    let latest = branch::load_latest(repository, branch_id)
        .await
        .unwrap_or_default();
    let name = branch::name(metadata).unwrap_or_default().to_string();
    let creator = branch::creator(metadata).unwrap_or_default().to_string();
    let category = branch::category(metadata).unwrap_or_default().to_string();
    let created = branch::created(metadata);
    let stack: Vec<model_v1::BranchPoint> = branch::stack(metadata)
        .iter()
        .map(model_v1::BranchPoint::from)
        .collect();
    // The metadata blob is already deserialized in scope, so reading the
    // PROTECT bit here costs no extra blob read on the BranchList/BranchGet
    // hot path.
    let protected = branch::protected(metadata);
    Ok(model_v1::Branch {
        id: branch_id.into(),
        name,
        creator,
        category,
        created,
        latest: latest.into(),
        deleted,
        metadata: metadata_hash.into(),
        stack,
        protected,
    })
}

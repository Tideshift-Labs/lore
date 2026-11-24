// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::interface::LoreGlobalArgs;

pub fn address_with_random_context(address: lore_storage::Address) -> lore_storage::Address {
    lore_storage::Address {
        context: rand::random::<lore_storage::Context>(),
        hash: address.hash,
    }
}

pub fn setup_test_execution() -> std::sync::Arc<lore_revision::interface::ExecutionContext> {
    std::sync::Arc::new(lore_revision::interface::ExecutionContext::new_client(
        LoreGlobalArgs::default(),
        lore_revision::relay::EventDispatcher::no_dispatch(),
    ))
}

pub fn allow_all_authorizer()
-> std::sync::Arc<dyn lore_server::authnz::repository_authorizer::RepositoryAuthorizer> {
    std::sync::Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer)
}

/// Permits every action, `owner` and `admin` included. `AllowAll` grants only
/// read/write/obliterate/presign (v0.13), so a test whose subject is the fork's own claim gate
/// uses this to keep the upstream authorizer checks out of the way.
pub struct PermitEveryAction;

#[async_trait::async_trait]
impl lore_server::authnz::repository_authorizer::RepositoryAuthorizer for PermitEveryAction {
    async fn check_repository_access(
        &self,
        _token: Option<&lore_server::authnz::repository_authorizer::VerifiedToken<'_>>,
        _repository_id: lore_revision::lore::RepositoryId,
        _action: lore_server::authnz::repository_authorizer::Action,
    ) -> Result<(), tonic::Status> {
        Ok(())
    }
}

pub fn permit_every_action_authorizer()
-> std::sync::Arc<dyn lore_server::authnz::repository_authorizer::RepositoryAuthorizer> {
    std::sync::Arc::new(PermitEveryAction)
}

/// Every push permitted, protected branches included: for tests of `push`
/// itself rather than of who may call it.
pub const PUSH_ANY: lore_server::grpc::handlers::branch_push::PushAccess =
    lore_server::grpc::handlers::branch_push::PushAccess {
        write: true,
        push_protected: true,
    };

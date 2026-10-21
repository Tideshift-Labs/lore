// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_revision::lore::RepositoryId;
use lore_storage::MutableStore;
use lore_storage::StoreError;
use tracing::debug;
use tracing::warn;

use crate::correlation::CorrelationId;
use crate::protocol::attribute_map::AttributeMap;
use crate::protocol::attribute_map::get_user_id_from_context;
use crate::protocol::storage::messages::LoreResponse;
use crate::protocol::storage::messages::Message;
use crate::protocol::storage::messages::MessageHandleError;
use crate::protocol::storage::messages::MessageParseError;
use crate::protocol::storage::messages::Response;
use crate::util::setup_execution;

#[derive(Clone, Debug, PartialEq)]
pub struct MutableStoreOp {
    pub key: Hash,
    pub value: Hash,
    pub key_type: KeyType,
}

impl MutableStoreOp {
    pub fn parse(bytes: Bytes) -> Result<Self, MessageParseError> {
        if bytes.len() < 2 * size_of::<Hash>() + 1 {
            return Err(MessageParseError::InvalidFieldLength);
        }

        let key = Hash::from(&bytes[..size_of::<Hash>()]);
        let value = Hash::from(&bytes[size_of::<Hash>()..2 * size_of::<Hash>()]);
        let key_type = KeyType::try_from(bytes[2 * size_of::<Hash>()])
            .map_err(|_err| MessageParseError::InvalidFieldLength)?;

        Ok(Self {
            key,
            value,
            key_type,
        })
    }
}

/// FORK-LOCAL (Tideshift): refuse a client write to a server-owned key type.
///
/// The seven generic mutable RPCs (v0 and v1 gRPC `MutableStore` and
/// `MutableCompareAndSwap`, and the `urc/0.2` and `lore-storage/0.4` QUIC
/// `MutableStore` and `MutableCas` commands) pass the wire `KeyType` through
/// and check only repository `write`. Without this, a writer could move a
/// branch tip or rewrite repository or branch metadata and skip push checks,
/// branch protection, locks and the event outbox. Every one of those RPCs
/// reaches the store through [`handle_mutable_store`] or
/// [`super::mutable_cas::handle_mutable_cas`], and nothing inside the server
/// calls either, so the check here covers every store backend and every
/// transport without touching server-internal writers (push, metadata set,
/// replication, the domain coordinator).
///
/// The fenced set is the CR-029 domain-owned set, so a new `KeyType` has to be
/// classified there before it compiles. Policy-independent and
/// enforcement-independent: an unarmed or non-Postgres cell refuses too.
pub fn refuse_domain_key(key_type: KeyType) -> Result<(), MessageHandleError> {
    if lore_postgres::domain::bypass::is_domain_owned(key_type) {
        warn!(
            ?key_type,
            "Refusing a client write to a server-owned key type"
        );
        return Err(MessageHandleError::DomainKeyRefused(key_type));
    }
    Ok(())
}

pub async fn handle_mutable_store(
    key: Hash,
    value: Hash,
    key_type: KeyType,
    repository: RepositoryId,
    correlation_id: String,
    user_id: String,
    mutable_store: Arc<dyn MutableStore>,
) -> Result<LoreResponse, MessageHandleError> {
    refuse_domain_key(key_type)?;
    let execution = setup_execution(module_path!(), correlation_id, user_id);

    debug!(
        "Handling mutable_store for key: {} key_type: {:?} in repository: {}",
        key, key_type, repository
    );

    LORE_CONTEXT
        .scope(execution, async move {
            match mutable_store.store(repository, key, value, key_type).await {
                Ok(()) => {
                    debug!("Successfully stored mutable key: {}", key);
                    Ok(LoreResponse::MutableStore(MutableStoreResponse::default()))
                }
                Err(StoreError::SlowDown(_)) => Err(MessageHandleError::SlowDown),
                Err(err) => {
                    warn!(error = ?err, "Failed to store mutable key: {}", key);
                    Err(MessageHandleError::from(err))
                }
            }
        })
        .await
}

#[async_trait]
impl Message for MutableStoreOp {
    async fn handle_mutable(
        &self,
        context: Arc<AttributeMap>,
        mutable_store: Arc<dyn MutableStore>,
    ) -> Result<LoreResponse, MessageHandleError> {
        let repository = *context
            .get_or::<RepositoryId, MessageHandleError>(MessageHandleError::NotConnected)?;
        let user_id = get_user_id_from_context(&context);
        let correlation_id = context.get::<CorrelationId>().unwrap_or_default();
        handle_mutable_store(
            self.key,
            self.value,
            self.key_type,
            repository,
            correlation_id.to_string(),
            user_id,
            mutable_store,
        )
        .await
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct MutableStoreResponse {}

impl Response for MutableStoreResponse {
    fn data(&self) -> Vec<Bytes> {
        vec![]
    }
}

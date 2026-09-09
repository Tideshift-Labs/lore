// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Journal operations. Child writes never load settled history.

use super::persistence::StoredChild;
use super::*;

#[async_trait]
impl AttemptStore for RepositoryAttemptStore {
    async fn record_managed(
        &self,
        record: &AttemptRecord,
        intent: &ManagedAttemptIntent,
    ) -> Result<(), ProtocolError> {
        if intent.version != 1
            || intent.repository != record.repository
            || intent.rpc != record.operation
        {
            return Err(ProtocolError::internal("managed child identity mismatch"));
        }
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load_for_write(&guard)?;
        let id = record.attempt_id.to_string();
        if self.child(&document, &id)?.is_some()
            || document.managed.iter().any(|child| child.attempt == id)
        {
            return Err(ProtocolError::internal(
                "managed child identity already dispatched",
            ));
        }
        let namespace = ManagedNamespace {
            repository: intent.repository.to_string(),
            endpoint: intent.endpoint.clone(),
            issuer: intent.verified_issuer.clone(),
            subject: intent.authenticated_subject.clone(),
            capabilities: intent.caller_capabilities.clone(),
        };
        let parent = document
            .parents
            .iter_mut()
            .find(|parent| parent.id == intent.parent_id.to_string())
            .ok_or_else(|| ProtocolError::internal("managed child has no durable parent"))?;
        if parent.version != 1
            || parent.complete
            || parent
                .namespace
                .as_ref()
                .is_some_and(|old| old != &namespace)
        {
            return Err(ProtocolError::internal(
                "managed parent namespace changed or closed",
            ));
        }
        if parent.namespace.is_none() {
            parent.namespace = Some(namespace);
            // A bound parent without a child is safe after a crash. The inverse is not.
            self.store(&guard, &document)?;
        }
        self.write_child(
            &document,
            &StoredChild::new(
                StoredAttempt::try_from(record)?,
                Some(StoredManagedIntent {
                    attempt: id,
                    parent: intent.parent_id.to_string(),
                    rpc: intent.rpc.clone(),
                    canonical_request: intent.canonical_request.clone(),
                }),
            ),
        )
    }

    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load_for_write(&guard)?;
        let id = record.attempt_id.to_string();
        let orphan = document
            .managed
            .iter()
            .position(|child| child.attempt == id);
        let existing = self.child(&document, &id)?;
        let managed = if let Some(index) = orphan {
            let intent = &document.managed[index];
            if existing
                .as_ref()
                .is_some_and(|(child, _)| child.managed.as_ref() != Some(intent))
            {
                return Err(ProtocolError::internal(
                    "legacy intent transition does not match stored child",
                ));
            }
            Some(intent.clone())
        } else {
            existing.and_then(|(child, _)| child.managed)
        };
        self.write_child(
            &document,
            &StoredChild::new(StoredAttempt::try_from(record)?, managed),
        )?;
        if let Some(index) = orphan {
            // Preserve ordinary record's v1 meaning: the old intent remains attached. Publish
            // its child before removing the root copy; a failed second publication cannot
            // acknowledge dispatch and leaves a fail-closed duplicate for admission.
            document.managed.remove(index);
            self.store(&guard, &document)?;
        }
        Ok(())
    }

    async fn lookup(&self, attempt: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let document = self.load(&guard)?;
        self.child(&document, &attempt.to_string())?
            .map(|(child, _)| AttemptRecord::try_from(&child.attempt))
            .transpose()
    }

    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let document = self.load(&guard)?;
        let mut records = self
            .children(&document, true)?
            .into_iter()
            .filter(|child| child.attempt.state.is_unresolved())
            .map(|child| AttemptRecord::try_from(&child.attempt))
            .collect::<Result<Vec<_>, _>>()?;
        records.sort_by(|left, right| {
            left.recorded_at_unix_millis
                .cmp(&right.recorded_at_unix_millis)
                .then_with(|| left.attempt_id.as_uuid().cmp(&right.attempt_id.as_uuid()))
        });
        Ok(records)
    }

    async fn record_ownership(&self, ownership: &LockOwnership) -> Result<(), ProtocolError> {
        let stored = StoredOwnership::from(ownership);
        self.update(|document| {
            match document
                .ownership
                .iter_mut()
                .find(|held| held.branch == stored.branch && held.resource == stored.resource)
            {
                Some(existing) => *existing = stored,
                None => document.ownership.push(stored),
            }
        })
        .await
    }

    async fn ownership_for(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError> {
        let document = self.read().await?;
        document
            .ownership
            .iter()
            .find(|held| {
                held.branch == branch.to_string() && held.resource == resource_hash.to_string()
            })
            .map(LockOwnership::try_from)
            .transpose()
    }

    async fn ownership_for_batch(
        &self,
        resources: &[(Context, Hash)],
    ) -> Result<Vec<Option<LockOwnership>>, ProtocolError> {
        let document = self.read().await?;
        resources
            .iter()
            .map(|(branch, resource)| {
                let branch = branch.to_string();
                let resource = resource.to_string();
                document
                    .ownership
                    .iter()
                    .find(|held| held.branch == branch && held.resource == resource)
                    .map(LockOwnership::try_from)
                    .transpose()
            })
            .collect()
    }

    async fn clear_ownership(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<(), ProtocolError> {
        let branch = branch.to_string();
        let resource = resource_hash.to_string();
        self.update(|document| {
            document
                .ownership
                .retain(|held| held.branch != branch || held.resource != resource)
        })
        .await
    }

    async fn clear_ownership_batch(
        &self,
        resources: &[(Context, Hash)],
    ) -> Result<(), ProtocolError> {
        if resources.is_empty() {
            return Ok(());
        }
        let cleared = resources
            .iter()
            .map(|(branch, resource)| (branch.to_string(), resource.to_string()))
            .collect::<std::collections::HashSet<_>>();
        self.update(|document| {
            document
                .ownership
                .retain(|held| !cleared.contains(&(held.branch.clone(), held.resource.clone())))
        })
        .await
    }

    async fn resolve(
        &self,
        attempt: &AttemptId,
        resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let document = self.load(&guard)?;
        if let Some((mut child, _)) = self.child(&document, &attempt.to_string())? {
            child.attempt.state = StoredState::from(&AttemptState::Resolved(resolution));
            self.write_child(&document, &child)?;
        }
        // Ownership outlives an attempt. Only confirmed release clears its token.
        Ok(())
    }
}

impl RepositoryAttemptStore {
    pub async fn reconcile_parent(&self, parent: Uuid) -> Result<(), ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load_for_write(&guard)?;
        let children = self.children(&document, false)?;
        let id = parent.to_string();
        if !children.iter().any(|child| {
            child
                .managed
                .as_ref()
                .is_some_and(|child| child.parent == id)
        }) && !document.managed.iter().any(|child| child.parent == id)
        {
            return Err(ProtocolError::internal(
                "parent has no positive child settlement evidence",
            ));
        }
        self.finish_loaded_parent(&guard, &mut document, parent, &children)
    }

    pub async fn record_workflow_child(
        &self,
        parent: Uuid,
        attempt: AttemptId,
        operation: String,
        canonical_intent: Vec<u8>,
    ) -> Result<(), ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let document = self.load_for_write(&guard)?;
        if !document
            .parents
            .iter()
            .any(|held| held.id == parent.to_string() && held.version == 1 && !held.complete)
            || self.child(&document, &attempt.to_string())?.is_some()
            || document
                .managed
                .iter()
                .any(|held| held.attempt == attempt.to_string())
        {
            return Err(ProtocolError::internal(
                "workflow parent missing or child already exists",
            ));
        }
        self.write_child(
            &document,
            &StoredChild::new(
                StoredAttempt::try_from(&AttemptRecord {
                    attempt_id: attempt,
                    state: AttemptState::Unresolved,
                    operation: operation.clone(),
                    repository: RepositoryId::from([0u8; 16]),
                    recorded_at_unix_millis: now_unix_millis(),
                    receipt: None,
                })?,
                Some(StoredManagedIntent {
                    attempt: attempt.to_string(),
                    parent: parent.to_string(),
                    rpc: operation,
                    canonical_request: canonical_intent,
                }),
            ),
        )
    }

    /// Admission and recovery call this once. Validate the full history here, never on each
    /// child admission or settlement, so damaged settled evidence still closes the write fence.
    pub async fn managed_parents(&self) -> Result<Vec<ManagedParent>, ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let document = self.load(&guard)?;
        self.validate_parents(&document)?;
        self.children(&document, false)?;
        Ok(document.parents)
    }

    pub(super) fn validate_parents(&self, document: &StoredDocument) -> Result<(), ProtocolError> {
        let mut seen = std::collections::HashSet::new();
        for parent in &document.parents {
            if parent.version != 1
                || !seen.insert(&parent.id)
                || parse_uuid(&parent.id, "managed parent")?.to_string() != parent.id
            {
                return Err(ProtocolError::internal(
                    "unsupported managed parent version or identity",
                ));
            }
        }
        let mut orphan_ids = std::collections::HashSet::new();
        for orphan in &document.managed {
            if parse_attempt_id(&orphan.attempt)?.to_string() != orphan.attempt
                || parse_uuid(&orphan.parent, "managed parent")?.to_string() != orphan.parent
                || !orphan_ids.insert(&orphan.attempt)
            {
                return Err(ProtocolError::internal(
                    "invalid legacy managed intent identity",
                ));
            }
        }
        for ownership in &document.ownership {
            LockOwnership::try_from(ownership)?;
        }
        Ok(())
    }

    pub async fn mark_parent_uncertain(&self, id: Uuid, code: i32) -> Result<(), ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load_for_write(&guard)?;
        let parent = document
            .parents
            .iter_mut()
            .find(|parent| parent.id == id.to_string())
            .ok_or_else(|| ProtocolError::internal("managed parent is missing"))?;
        parent.parent_uncertainty_code = Some(code);
        parent.complete = false;
        self.store(&guard, &document)
    }

    pub async fn complete_parent_body(&self, id: Uuid) -> Result<(), ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load_for_write(&guard)?;
        let parent = document
            .parents
            .iter_mut()
            .find(|parent| parent.id == id.to_string())
            .ok_or_else(|| ProtocolError::internal("managed parent is missing"))?;
        if parent.parent_uncertainty_code.is_some() {
            return Err(ProtocolError::internal(
                "parent uncertainty requires independent evidence",
            ));
        }
        parent.body_completed = true;
        self.store(&guard, &document)
    }

    pub async fn begin_parent(&self, parent: ManagedParent) -> Result<(), ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load_for_write(&guard)?;
        self.validate_parents(&document)?;
        if document
            .parents
            .iter()
            .any(|old| !old.complete || old.id == parent.id)
            || self
                .children(&document, false)?
                .iter()
                .any(|child| child.attempt.state.is_unresolved())
        {
            return Err(ProtocolError::internal(
                "repository has an unresolved managed workflow",
            ));
        }
        document.parents.push(parent);
        self.validate_parents(&document)?;
        self.store(&guard, &document)
    }

    pub async fn bind_parent_namespace(
        &self,
        id: Uuid,
        binding: &CallerRecoveryContext,
    ) -> Result<(), ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load_for_write(&guard)?;
        let namespace = ManagedNamespace {
            repository: binding.repository.to_string(),
            endpoint: binding.endpoint.clone(),
            issuer: binding.verified_issuer.clone(),
            subject: binding.authenticated_subject.clone(),
            capabilities: binding.caller_capabilities.clone(),
        };
        let parent = document
            .parents
            .iter_mut()
            .find(|parent| parent.id == id.to_string())
            .ok_or_else(|| ProtocolError::internal("managed parent is missing"))?;
        if parent.version != 1
            || parent.complete
            || parent
                .namespace
                .as_ref()
                .is_some_and(|old| old != &namespace)
        {
            return Err(ProtocolError::internal(
                "managed parent namespace changed or closed",
            ));
        }
        if parent.namespace.is_none() {
            parent.namespace = Some(namespace);
            self.store(&guard, &document)?;
        }
        Ok(())
    }

    pub async fn finish_parent(&self, parent: Uuid) -> Result<(), ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load_for_write(&guard)?;
        let children = self.children(&document, false)?;
        self.finish_loaded_parent(&guard, &mut document, parent, &children)
    }

    fn finish_loaded_parent(
        &self,
        guard: &FSLock,
        document: &mut StoredDocument,
        parent: Uuid,
        children: &[StoredChild],
    ) -> Result<(), ProtocolError> {
        self.validate_parents(document)?;
        if children
            .iter()
            .any(|child| child.attempt.state.is_unresolved())
        {
            return Err(ProtocolError::internal(
                "workflow outcome remains unknown; use operation status",
            ));
        }
        let parent = document
            .parents
            .iter_mut()
            .find(|held| held.id == parent.to_string())
            .ok_or_else(|| ProtocolError::internal("managed parent is missing"))?;
        if parent.parent_uncertainty_code.is_some() || !parent.body_completed {
            return Err(ProtocolError::internal(
                "parent uncertainty requires independent body completion evidence",
            ));
        }
        parent.complete = true;
        self.store(guard, document)
    }

    pub async fn recovery_context(
        &self,
        attempt: &AttemptId,
    ) -> Result<CallerRecoveryContext, ProtocolError> {
        let _local = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let document = self.load(&guard)?;
        let managed = self
            .child(&document, &attempt.to_string())?
            .and_then(|(child, _)| child.managed)
            .or_else(|| {
                document
                    .managed
                    .iter()
                    .find(|child| child.attempt == attempt.to_string())
                    .cloned()
            })
            .ok_or_else(|| ProtocolError::internal("attempt has no managed namespace"))?;
        let namespace = document
            .parents
            .iter()
            .find(|parent| parent.id == managed.parent)
            .and_then(|parent| parent.namespace.as_ref())
            .ok_or_else(|| ProtocolError::internal("parent namespace is missing"))?;
        Ok(CallerRecoveryContext {
            repository: namespace
                .repository
                .parse()
                .map_err(|_| ProtocolError::internal("invalid repository identity"))?,
            endpoint: namespace.endpoint.clone(),
            verified_issuer: namespace.issuer.clone(),
            authenticated_subject: namespace.subject.clone(),
            caller_capabilities: namespace.capabilities.clone(),
        })
    }
}

// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Explicit sequential repository stages within one fenced push command.
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use lore_base::types::RepositoryId;
use lore_error_set::prelude::*;
use lore_transport::AttemptStore;
use lore_transport::CallerOperationContext;
use lore_transport::ProtocolError;
use uuid::Uuid;

use crate::attempt_store::RepositoryAttemptStore;
use crate::repository_fence::RepositoryMutationGuard;

/// Optional second journal; the shared worktree parent is durable before these hooks run.
#[async_trait]
pub trait ManagedPushObserver: Send + Sync {
    async fn begin_stage(
        &self,
        parent: Uuid,
        repository: RepositoryId,
        shared: Arc<RepositoryAttemptStore>,
        label: &str,
    ) -> Result<Arc<dyn AttemptStore>, ProtocolError>;
    async fn complete_stage_body(&self, parent: Uuid, status: i32) -> Result<(), ProtocolError>;
    async fn finish_stage(&self, parent: Uuid) -> Result<(), ProtocolError>;
}

pub struct ManagedPushRunner {
    guard: Arc<RepositoryMutationGuard>,
    observer: Option<Arc<dyn ManagedPushObserver>>,
    serial: tokio::sync::Mutex<()>,
    blocked: AtomicBool,
}

impl ManagedPushRunner {
    pub fn new(
        guard: Arc<RepositoryMutationGuard>,
        observer: Option<Arc<dyn ManagedPushObserver>>,
    ) -> Self {
        Self {
            guard,
            observer,
            serial: tokio::sync::Mutex::new(()),
            blocked: AtomicBool::new(false),
        }
    }

    /// Only trusted push orchestration chooses a new repository stage. Dispatch never retargets.
    pub async fn run_stage<T, E, F>(
        &self,
        repository: RepositoryId,
        label: &str,
        future: F,
    ) -> Result<T, E>
    where
        E: ErrorSet + lore_error_set::HasAll<<ProtocolError as ErrorSet>::Variants> + FfiError,
        F: Future<Output = Result<T, E>>,
    {
        if lore_transport::has_managed_caller() {
            return Err(ProtocolError::internal(
                "Cannot nest a managed push stage in an existing caller",
            ))
            .forward::<E>("admitting push stage");
        }
        let _serial = self.serial.lock().await;
        if self.blocked.swap(true, Ordering::SeqCst) {
            return Err(ProtocolError::internal(
                "A previous push stage remains unresolved",
            ))
            .forward::<E>("admitting push stage");
        }
        // Cancellation, panic, and journal failure leave both this runner and durable admission blocked.
        let parent = Uuid::now_v7();
        let shared = self
            .guard
            .begin(
                parent,
                "push-stage".to_owned(),
                format!("repository={repository}; stage={label}"),
            )
            .await
            .forward::<E>("beginning push stage")?;
        let attempts: Arc<dyn AttemptStore> = match &self.observer {
            Some(observer) => observer
                .begin_stage(parent, repository, shared.clone(), label)
                .await
                .forward::<E>("beginning observer push stage")?,
            None => shared.clone(),
        };
        let context = CallerOperationContext::new(parent, repository, attempts);
        let result = lore_transport::with_caller_operation(context, future).await;
        let status = result.as_ref().err().map_or(0, FfiError::ffi_code);
        let body = async {
            if status == 194 {
                shared.mark_parent_uncertain(parent, status).await?;
            } else {
                shared.complete_parent_body(parent).await?;
            }
            if let Some(observer) = &self.observer {
                observer.complete_stage_body(parent, status).await?;
            }
            Ok::<_, ProtocolError>(())
        }
        .await;
        if let Err(error) = body {
            // Retain the original ambiguous attempt identity even when its body marker cannot publish.
            if status == 193 || status == 194 {
                return result;
            }
            return Err(error).forward::<E>("completing push stage body");
        }
        if status != 193 && status != 194 {
            // Stage completion never completes the outer UI workflow. Finish its app record
            // first so an observer failure cannot release the shared worktree blocker.
            if let Some(observer) = &self.observer {
                observer
                    .finish_stage(parent)
                    .await
                    .forward::<E>("finishing observer push stage")?;
            }
            self.guard
                .finish(parent)
                .await
                .forward::<E>("finishing shared push stage")?;
            self.blocked.store(false, Ordering::SeqCst);
        }
        result
    }
}

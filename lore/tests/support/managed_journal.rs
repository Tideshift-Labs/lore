// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! In-memory observation only. Production durability is tested in the journal owner's suite.

use std::collections::HashMap;
use std::sync::Mutex;

use lore_base::types::{Context, Hash};
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::{AttemptId, AttemptRecord, AttemptResolution, AttemptStore, LockOwnership, ProtocolError, VolatileAttemptStore};

pub const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

#[derive(Default)]
pub struct ManagedJournal {
    inner: VolatileAttemptStore,
    intents: Mutex<HashMap<uuid::Uuid, ManagedAttemptIntent>>,
}

impl ManagedJournal {
    pub fn intents(&self) -> HashMap<uuid::Uuid, ManagedAttemptIntent> {
        self.intents.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl AttemptStore for ManagedJournal {
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> { self.inner.record(record).await }
    async fn record_managed(&self, record: &AttemptRecord, intent: &ManagedAttemptIntent) -> Result<(), ProtocolError> {
        assert_eq!(record.operation, intent.rpc);
        assert_eq!(record.repository, intent.repository);
        assert_eq!(intent.caller_capabilities, "outcome_unknown_v1");
        assert_eq!(intent.authenticated_subject, "fixture-user");
        self.inner.record(record).await?;
        self.intents.lock().unwrap().insert(record.attempt_id.as_uuid(), intent.clone());
        Ok(())
    }
    async fn lookup(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> { self.inner.lookup(id).await }
    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> { self.inner.unresolved().await }
    async fn resolve(&self, id: &AttemptId, resolution: AttemptResolution) -> Result<(), ProtocolError> { self.inner.resolve(id, resolution).await }
    async fn record_ownership(&self, _: &LockOwnership) -> Result<(), ProtocolError> { unreachable!("product journal never stores ownership") }
    async fn ownership_for(&self, _: &Context, _: &Hash) -> Result<Option<LockOwnership>, ProtocolError> { unreachable!("product journal never stores ownership") }
    async fn clear_ownership(&self, _: &Context, _: &Hash) -> Result<(), ProtocolError> { unreachable!("product journal never stores ownership") }
}

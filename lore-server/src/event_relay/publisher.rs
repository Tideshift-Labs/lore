// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The relay's publisher seam.
//!
//! WP-111 owns `plugins::remote_notification` and this step does not edit it,
//! so the abstraction lives here and the implementation for
//! [`PrivateGatewayClient`] is written on this side of the boundary. That is
//! the whole reason the trait exists: it lets a test drive the worker's
//! claim/acknowledge/requeue decisions without a gateway, while a component
//! test that wants the **real** classification instead builds a genuine
//! `PrivateGatewayClient` over WP-111's `FakeGateway` transport and reaches this
//! same impl.
//!
//! Nothing here retries. CR-032 puts the retry decision on the relay, because
//! only the relay holds the claim that makes a retry safe.

use std::time::Duration;

use async_trait::async_trait;

use crate::plugins::remote_notification::BrokerAcceptance;
use crate::plugins::remote_notification::DurableEnvelopeV1;
use crate::plugins::remote_notification::PrivateGatewayClient;
use crate::plugins::remote_notification::PublishFailure;

/// One durable publication attempt.
#[async_trait]
pub trait DurablePublisher: Send + Sync + std::fmt::Debug {
    /// Publish one envelope, bounded by `deadline`.
    ///
    /// Exactly one attempt. A `PublishFailure` is a classification, not an
    /// instruction to try again.
    async fn publish(
        &self,
        envelope: &DurableEnvelopeV1,
        deadline: Duration,
    ) -> Result<BrokerAcceptance, PublishFailure>;
}

#[async_trait]
impl DurablePublisher for PrivateGatewayClient {
    async fn publish(
        &self,
        envelope: &DurableEnvelopeV1,
        deadline: Duration,
    ) -> Result<BrokerAcceptance, PublishFailure> {
        self.publish_durable_invalidation(envelope, deadline).await
    }
}

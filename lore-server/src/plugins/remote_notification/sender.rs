// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The bounded best-effort `LIVE_HINT` sender and its single drain worker.
//!
//! ## The one rule this module exists to keep
//!
//! **A live hint never changes the result of a mutation that already
//! committed.** Every path out of [`RemoteNotificationSender`] is infallible
//! and non-blocking: the mutation thread does a `try_send` into a bounded
//! queue and returns. A full queue, a dead gateway, an exhausted retry budget,
//! and a locally-rejected envelope all end the same way — a metric, a protected
//! log line, and a dropped hint. Clients reconcile by bounded replay and
//! authoritative refetch, which is exactly what the contract says loss and
//! duplication cost on this class.
//!
//! ## Shape
//!
//! One bounded `mpsc` queue and exactly one worker task, never a task per
//! event and never an unbounded channel. The worker publishes serially with a
//! bounded jittered retry budget, so a slow gateway shows up as queue pressure
//! and drops rather than as unbounded concurrency against the gateway.
//!
//! The stable event id is minted once, in [`RemoteNotificationSender::enqueue`],
//! before the hint enters the queue. Every retry of that publication reuses it,
//! and it is also the public event's own `id`, so a gateway, a broker, and a
//! desktop subscriber all name one event by one identifier.

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Hash;
use lore_base::types::LockResource;
use lore_base::types::RepositoryId;
use lore_proto::lock;
use lore_proto::lore::notification;
use lore_revision::lore::BranchId;
use lore_revision::notification::NotificationError;
use lore_revision::util::time::RetryPolicy;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::client::PrivateGatewayClient;
use super::config::RemoteNotificationConfig;
use super::envelope::EnvelopeCommon;
use super::envelope::EventId;
use super::envelope::HintEnvelopeV1;
use super::metrics;
use crate::plugins::PluginError;

/// The immutable producer identity every envelope this sender builds carries.
#[derive(Clone, Debug)]
struct ProducerIdentity {
    cell_id: String,
    placement_epoch: u64,
    producer_instance_id: String,
}

/// The bounded live-hint sender.
///
/// Cloneable through `Arc` by the server; the queue handle is what is shared.
#[derive(Clone, Debug)]
pub struct RemoteNotificationSender {
    queue: mpsc::Sender<HintEnvelopeV1>,
    identity: ProducerIdentity,
    /// `true` publishes to `.shadow` only. Shadow envelopes are
    /// observation-only and can never reach a public or durable side effect.
    shadow: bool,
    /// Signals the worker to stop accepting and start its bounded drain.
    drain: CancellationToken,
}

/// The single worker future that drains the queue.
///
/// Returned from the factory as a `NotificationReceiver`, so the server's
/// `JoinSet` owns its lifecycle exactly as it does for any other plugin task.
pub struct LiveHintWorker {
    queue: mpsc::Receiver<HintEnvelopeV1>,
    client: PrivateGatewayClient,
    retry_policy: RetryPolicy,
    drain_timeout: std::time::Duration,
    drain: CancellationToken,
    delivery_class: &'static str,
}

/// Builds a sender and its worker over one bounded queue.
pub fn build(
    config: &RemoteNotificationConfig,
    client: PrivateGatewayClient,
    shadow: bool,
) -> (Arc<RemoteNotificationSender>, LiveHintWorker) {
    let (tx, rx) = mpsc::channel(config.queue_capacity);
    let drain = CancellationToken::new();
    let retry_policy = RetryPolicy::builder()
        .with_initial_backoff(config.retry.initial_backoff)
        .with_max_backoff(config.retry.max_backoff)
        .with_limit(config.retry.limit)
        .build();
    let delivery_class = if shadow {
        metrics::CLASS_SHADOW
    } else {
        metrics::CLASS_LIVE_HINT
    };

    let sender = Arc::new(RemoteNotificationSender {
        queue: tx,
        identity: ProducerIdentity {
            cell_id: config.cell_id.clone(),
            placement_epoch: config.placement_epoch,
            producer_instance_id: config.producer_instance_id.clone(),
        },
        shadow,
        drain: drain.clone(),
    });
    let worker = LiveHintWorker {
        queue: rx,
        client,
        retry_policy,
        drain_timeout: config.drain_timeout,
        drain,
        delivery_class,
    };
    (sender, worker)
}

impl RemoteNotificationSender {
    /// Stops new enqueue and asks the worker to drain what it already accepted,
    /// within the configured drain timeout.
    ///
    /// Nothing in `lore-server` calls this yet: the `NotificationPlugin` seam
    /// has no shutdown hook, so wiring it to the server's drain sequence is
    /// WP-119's `SCHEMA-119` step. Until then the worker still drains on its own
    /// when every sender handle is dropped.
    pub fn begin_drain(&self) {
        self.drain.cancel();
    }

    /// Current queue occupancy, for the diagnostics surface.
    pub fn queued(&self) -> usize {
        self.queue.max_capacity() - self.queue.capacity()
    }

    /// The configured ordinary queue capacity, for the diagnostics surface.
    pub fn capacity(&self) -> usize {
        self.queue.max_capacity()
    }

    /// Wraps a public event in a private envelope and offers it to the bounded
    /// queue. Infallible and non-blocking by construction.
    fn enqueue(&self, repository: RepositoryId, event: notification::event::Event) {
        if self.drain.is_cancelled() {
            self.refuse(repository, metrics::ENQUEUE_SHUTTING_DOWN);
            return;
        }

        let event_id = EventId::new_v4();
        let now = SystemTime::now();
        let hint = HintEnvelopeV1 {
            common: EnvelopeCommon {
                cell_id: self.identity.cell_id.clone(),
                placement_epoch: self.identity.placement_epoch,
                event_id,
                repository,
                producer_instance_id: self.identity.producer_instance_id.clone(),
                produced_at: now,
            },
            shadow: self.shadow,
            lore_event: notification::Event {
                // The envelope's stable event id and the public event's id are
                // the same UUID. A retry reuses both.
                id: event_id.to_hyphenated(),
                time: Some(prost_types::Timestamp::from(now)),
                repository: Bytes::copy_from_slice(repository.data()),
                event: Some(event),
            },
        };

        match self.queue.try_send(hint) {
            Ok(()) => metrics::record_queue_depth_delta(1),
            Err(mpsc::error::TrySendError::Full(hint)) => {
                self.drop_hint(&hint, metrics::ENQUEUE_QUEUE_FULL);
            }
            Err(mpsc::error::TrySendError::Closed(hint)) => {
                self.drop_hint(&hint, metrics::ENQUEUE_SHUTTING_DOWN);
            }
        }
    }

    fn refuse(&self, repository: RepositoryId, reason: &'static str) {
        metrics::record_enqueue_failure(reason);
        metrics::record_dropped_hint(self.delivery_class(), reason);
        tracing::warn!(
            reason,
            repository = %hex::encode(repository.data()),
            "remote notification live hint refused; the mutation result is unaffected"
        );
    }

    fn drop_hint(&self, hint: &HintEnvelopeV1, reason: &'static str) {
        metrics::record_enqueue_failure(reason);
        metrics::record_dropped_hint(self.delivery_class(), reason);
        // Repository and event id are protected structured-log fields, never
        // metric labels.
        tracing::warn!(
            reason,
            repository = %hex::encode(hint.common.repository.data()),
            event_id = %hint.common.event_id.to_hyphenated(),
            "remote notification live hint dropped at the bounded queue; the mutation result is \
             unaffected and clients reconcile by refetch"
        );
    }

    fn delivery_class(&self) -> &'static str {
        if self.shadow {
            metrics::CLASS_SHADOW
        } else {
            metrics::CLASS_LIVE_HINT
        }
    }

    fn resources(resources: &[LockResource]) -> Vec<lock::Resource> {
        resources
            .iter()
            .map(|res| lock::Resource {
                branch: Bytes::from(res.branch),
                hash: Bytes::from(res.hash),
                description: res.description.clone(),
                // A notification describes a lock, it does not authorize one;
                // the ownership token never travels on this path.
                expected_ownership_token: Default::default(),
            })
            .collect()
    }
}

impl LiveHintWorker {
    /// Drains the queue until shutdown, then drains what was already accepted
    /// within the configured bound.
    ///
    /// # Errors
    /// Never returns `Err` today. The signature matches `NotificationReceiver`
    /// so a future receiver task in this component can fail readiness through
    /// the same channel.
    pub async fn run(mut self) -> Result<(), PluginError> {
        tracing::info!(
            delivery_class = self.delivery_class,
            "remote notification live-hint worker started"
        );
        loop {
            // The select's result is bound before it is handled, so the
            // `&mut self.queue` borrow the receive future holds ends before
            // `publish_with_bounded_retry` takes `&self`.
            let next = tokio::select! {
                // Cancellation wins, deliberately. This loop has no time bound,
                // so if it kept consuming a full queue after a drain request the
                // configured `drain_timeout` would bound nothing. Leaving
                // immediately hands every remaining accepted event to
                // `drain_accepted`, which is where the bound lives.
                biased;
                () = self.drain.cancelled() => None,
                // A closed queue also leaves the loop; the drain below then
                // publishes whatever is still buffered.
                hint = self.queue.recv() => hint,
            };
            let Some(hint) = next else { break };
            metrics::record_queue_depth_delta(-1);
            self.publish_with_bounded_retry(hint).await;
        }
        self.drain_accepted().await;
        tracing::info!(
            delivery_class = self.delivery_class,
            "remote notification live-hint worker stopped"
        );
        Ok(())
    }

    /// Publishes what the queue already accepted, within the drain bound.
    ///
    /// This never *waits* for a new event. By the time it runs, either every
    /// sender handle is gone or `begin_drain` has been called, and
    /// [`RemoteNotificationSender::enqueue`] refuses once the drain token is
    /// cancelled — so an empty queue means the drain is finished, and blocking
    /// on `recv` would burn the whole drain bound on an idle cell. The bound
    /// therefore caps the time spent *publishing*, checked before each event,
    /// rather than the time spent waiting.
    ///
    /// The queue holds at most `queue_capacity` events, so this terminates.
    /// Anything still queued when the bound elapses is a counted drop, not a
    /// silent loss.
    ///
    /// **The receiver is closed first**, before anything is drained. That is
    /// what closes the enqueue race: a mutation thread that passed `enqueue`'s
    /// cancellation check just before `begin_drain` now gets
    /// `TrySendError::Closed` from its `try_send`, which `enqueue` already
    /// counts as a dropped hint. Without the close it could land in the buffer
    /// after this loop saw the queue empty, leaving an uncounted loss and a
    /// permanently skewed queue-depth gauge.
    async fn drain_accepted(&mut self) {
        let deadline = tokio::time::Instant::now() + self.drain_timeout;
        self.queue.close();

        let mut abandoned = 0u64;
        loop {
            let Ok(hint) = self.queue.try_recv() else {
                // Empty or already closed: every accepted event is accounted
                // for and nothing further can arrive.
                break;
            };
            metrics::record_queue_depth_delta(-1);
            if abandoned > 0 || tokio::time::Instant::now() >= deadline {
                abandoned += 1;
                self.abandon(&hint);
                continue;
            }
            self.publish_with_bounded_retry(hint).await;
        }

        if abandoned > 0 {
            tracing::warn!(
                abandoned,
                delivery_class = self.delivery_class,
                "remote notification drain bound elapsed with hints still queued"
            );
        }
    }

    /// Counts and logs one hint abandoned at the drain bound.
    fn abandon(&self, hint: &HintEnvelopeV1) {
        metrics::record_dropped_hint(self.delivery_class, "drain_timeout");
        tracing::warn!(
            repository = %hex::encode(hint.common.repository.data()),
            event_id = %hint.common.event_id.to_hyphenated(),
            "remote notification live hint abandoned at the drain bound"
        );
    }

    /// One publication: bounded attempts, jittered backoff, one stable event id
    /// throughout. An exhausted budget is a visible dropped hint.
    async fn publish_with_bounded_retry(&self, hint: HintEnvelopeV1) {
        let mut retry = self.retry_policy.retry();
        loop {
            match self.client.publish_hint(&hint).await {
                Ok(_acceptance) => return,
                Err(failure) => {
                    if !failure.is_retryable() || !retry.wait().await {
                        metrics::record_dropped_hint(self.delivery_class, failure.class_label());
                        tracing::warn!(
                            failure = %failure,
                            attempts = retry.counter() + 1,
                            repository = %hex::encode(hint.common.repository.data()),
                            event_id = %hint.common.event_id.to_hyphenated(),
                            "remote notification live hint dropped after a bounded publish \
                             budget; the mutation result is unaffected"
                        );
                        return;
                    }
                    metrics::record_publish_retry(self.delivery_class);
                }
            }
        }
    }
}

#[async_trait]
impl lore_revision::notification::NotificationSender for RemoteNotificationSender {
    async fn branch_created(&self, repository: RepositoryId, branch: BranchId) {
        self.enqueue(
            repository,
            notification::event::Event::BranchCreated(notification::BranchCreated {
                branch: Bytes::from_owner(branch),
            }),
        );
    }

    async fn branch_pushed(
        &self,
        repository: RepositoryId,
        branch: BranchId,
        user_id: &str,
        revision: Hash,
        revision_number: u64,
    ) {
        self.enqueue(
            repository,
            notification::event::Event::BranchPushed(notification::BranchPushed {
                revision: Bytes::from_owner(revision),
                revision_number,
                branch: Bytes::from_owner(branch),
                user_id: user_id.to_string(),
            }),
        );
    }

    async fn branch_deleted(&self, repository: RepositoryId, branch: BranchId) {
        self.enqueue(
            repository,
            notification::event::Event::BranchDeleted(notification::BranchDeleted {
                branch: Bytes::from_owner(branch),
            }),
        );
    }

    async fn resource_locked(
        &self,
        repository: RepositoryId,
        _branch: BranchId,
        user_id: &str,
        resources: &[LockResource],
    ) {
        self.enqueue(
            repository,
            notification::event::Event::ResourceLocked(notification::ResourceLocked {
                user_id: user_id.to_string(),
                resources: Self::resources(resources),
            }),
        );
    }

    async fn resource_unlocked(
        &self,
        repository: RepositoryId,
        _branch: BranchId,
        user_id: &str,
        resources: &[LockResource],
    ) {
        self.enqueue(
            repository,
            notification::event::Event::ResourceUnlocked(notification::ResourceUnlocked {
                user_id: user_id.to_string(),
                resources: Self::resources(resources),
            }),
        );
    }

    /// Obliterate propagation is a live hint like any other. It returns `Ok`
    /// unconditionally: a hint that could not be enqueued must not fail the
    /// obliterate that already happened.
    async fn obliterate(
        &self,
        repository: RepositoryId,
        address: Address,
    ) -> Result<(), NotificationError> {
        self.enqueue(
            repository,
            notification::event::Event::Obliterate(notification::Obliterate {
                address: Some(lore_proto::model::Address::from(address)),
                repository: Bytes::copy_from_slice(repository.data()),
            }),
        );
        Ok(())
    }

    /// Compliance-check events have no `lore.notification.Event` variant, so
    /// there is nothing to map into a transport-version-1 body without
    /// inventing one. Local mode no-ops here too; this stays aligned with it
    /// rather than diverging silently.
    async fn compliance_check(
        &self,
        _stream_name: &str,
        _repository: RepositoryId,
        _branch: BranchId,
        _user_id: &str,
        _revision: Hash,
        _revision_number: u64,
        _ip_addr: Option<String>,
    ) {
    }
}

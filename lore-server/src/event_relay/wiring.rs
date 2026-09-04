// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Server construction for the relay (WP-119 Step B, `SCHEMA-119`).
//!
//! All of the relay's boot-time decisions live here rather than in `server.rs`,
//! so the common server file gains one call and this module owns the rest. That
//! matters beyond tidiness: the checks below are a fail-closed sequence, and
//! keeping them in one function is what makes their order reviewable.
//!
//! The sequence, in order and for a reason:
//!
//! 1. **Not configured, or `enabled = false`** — return `None`. No pool, no
//!    task, no readiness handle. This is the state every cell is in today.
//! 2. **Configuration bounds** — `[outbox_relay]` must be inside CR-032's
//!    reviewed bounds. A refusal here names the field.
//! 3. **Notification mode** — must be `remote`. The relay publishes through
//!    WP-111's private gateway client, which only that mode configures.
//! 4. **`[plugins.remote]`** — must parse. A successful parse is also what
//!    proves the cell has a valid, non-empty `cell_id`, because that field is
//!    required and grammar-checked there.
//! 5. **Postgres mode** — there must be a domain coordinator, because the
//!    outbox lives in cell Postgres and its database identity is the thing the
//!    relay pool is checked against.
//! 6. **Startup enforcement** — co-location, schema state present, relay
//!    contract compatible, cutover marker complete.
//!
//! Only then is a pool built and a client connected.
//!
//! # Why this is two functions and not one
//!
//! [`prepare_event_relay`] runs the whole sequence above and spawns nothing;
//! [`spawn_event_relay`] attaches the admission gate and starts the tasks. The
//! split exists because of one ordering constraint in `server.rs`: a cell that
//! declares `[plugins.remote.receiver]` needs the relay's Postgres pool and its
//! gateway channel handed to the **notification plugin at construction**, since
//! the durable receiver is one of that plugin's own `receivers` and the server's
//! `JoinSet` owns its lifecycle. So the relay's inputs have to exist before
//! `configure_notification` runs, and the receiver's readiness handle only
//! exists after it. Preparation, plugin construction, then spawn is the only
//! order that satisfies both, and folding it back into one call would mean
//! either a second Postgres pool or a receiver whose facet reaches nothing.
//!
//! The refusal ordering is unchanged by the split: the notification-mode check
//! is still the third thing [`prepare_event_relay`] does and still runs before
//! any Postgres or gateway I/O, so a misconfigured mode is reported by the mode
//! check rather than by a confusing connect failure.
//!
//! # A receiver without a relay is refused, not ignored
//!
//! [`prepare_event_relay`] checks for `[plugins.remote.receiver]` **before** it
//! returns `None` for a disabled relay, and refuses with
//! [`StartupRefusal::ReceiverWithoutRelay`]. The receiver consumes on the
//! relay's own pool and channel, so on a relay-less cell it could only be
//! silently absent — and a cell with no receiver reports the same empty
//! checkpoint vector as a cell whose receiver is perfectly caught up.

use std::sync::Arc;

use anyhow::Result;
use anyhow::anyhow;
use lore_base::lore_spawn;
use lore_postgres::domain::DatabaseIdentity;
use lore_postgres::pool::Pool;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::info;

use crate::domain::DomainContext;
use crate::event_relay::admission::OutboxAdmission;
use crate::event_relay::config::EventRelayConfig;
use crate::event_relay::envelope_map::EnvelopeSource;
use crate::event_relay::evaluator_task::ConsumerSafetyTask;
use crate::event_relay::publisher::DurablePublisher;
use crate::event_relay::readiness::EventRelayReadiness;
use crate::event_relay::reset_service::StreamResetHandler;
use crate::event_relay::startup;
use crate::event_relay::startup::StartupRefusal;
use crate::event_relay::worker::EventRelayWorker;
use crate::plugins::remote_notification::NoopInvalidationTarget;
use crate::plugins::remote_notification::PrivateGatewayClient;
use crate::plugins::remote_notification::PublishTransport;
use crate::plugins::remote_notification::ReceiverReadiness;
use crate::plugins::remote_notification::ReceiverRuntime;
use crate::plugins::remote_notification::RemoteNotificationConfig;
use crate::plugins::remote_notification::client::GrpcPublishTransport;
use crate::plugins::remote_notification::client::connect_gateway_channel;
use crate::plugins::remote_notification::receiver_store::PostgresReceiverStore;
use crate::plugins::remote_notification::stream::GrpcDurableStream;
use crate::settings::Settings;
use crate::store::configuration::resolve_plugin_config_with_fallback;

/// The `mode` string that selects the Postgres backend.
const POSTGRES_MODE: &str = "postgres";
/// The `[notification] mode` the relay requires.
const REMOTE_NOTIFICATION_MODE: &str = "remote";

/// Connections in the relay's own pool.
///
/// The publish loop is strictly sequential — one claim transaction, then one
/// single-statement write per row — so its real concurrency is one. Step C adds
/// two more borrowers on the same pool: the consumer-safety evaluator's own
/// tick, and the stream-reset service, which takes a connection only when
/// WP-110 actually reports a reset. Four leaves each of the three a connection
/// and one spare, so a readiness probe never queues behind a claim and a reset
/// receipt never queues behind a prune batch.
///
/// It is deliberately **not** the domain coordinator's pool. That pool is sized
/// for a subsystem that is idle until cutover, and a long-running loop
/// borrowing from it would contend with the mutation transactions it exists to
/// serve.
///
/// TODO(WP-119 Phase 8): this is a sixth pool, outside the five-pool maxima
/// `FragmentProcessPoolInventory` checks against the process budget. Fold it
/// into that accounting the next time the inventory is revised; two
/// connections is small enough not to move the sum today, which is why it is a
/// constant rather than a knob.
const RELAY_POOL_MAX: u32 = 4;

/// What server composition keeps after the relay is wired.
pub struct EventRelayHandles {
    /// Facets for the readiness surface.
    pub readiness: Arc<EventRelayReadiness>,
    /// The frozen `StreamResetService`, for registration on the internal gRPC
    /// endpoint.
    ///
    /// Handed out rather than registered here because the internal endpoint is
    /// built later in server composition, from its own builder. Registration is
    /// therefore gated on this being `Some`, which it is only when the relay is
    /// enabled and every startup precondition passed.
    pub reset_service: Arc<StreamResetHandler>,
    /// Required-event mutation admission.
    ///
    /// Already attached to the `DomainContext` by [`spawn_event_relay`],
    /// and refreshed by the worker's readiness tick. Returned as well so the
    /// operator surface can report the gate's own limits and current verdict
    /// without going through the coordinator.
    pub admission: Arc<OutboxAdmission>,
}

/// Everything the relay needs, built and proven but not yet running.
///
/// Held by server construction across `configure_notification`, because the
/// durable receiver this carries has to reach the notification plugin at
/// construction time. See this module's "Why this is two functions" section.
pub struct EventRelayPreparation {
    pool: Pool,
    config: EventRelayConfig,
    publisher: Arc<dyn DurablePublisher>,
    readiness: Arc<EventRelayReadiness>,
    admission: Arc<OutboxAdmission>,
    domain: Arc<DomainContext>,
    cell_id: String,
    source: EnvelopeSource,
    receiver: Option<DurableReceiverWiring>,
}

/// What common server construction hands the `remote` notification plugin so it
/// is built with a live durable receiver attached.
///
/// Both halves come from the relay's own preparation on purpose. The transport
/// is the one the relay publishes over, so the receiver and the publisher share
/// one channel, one mTLS identity, and one view of gateway reachability; the
/// runtime's store is on the relay's own pool, so a receiver reads the
/// membership and checkpoint rows in the same database the relay was positively
/// proven co-located with.
#[derive(Clone)]
pub struct DurableReceiverWiring {
    /// The relay's own publish transport, for
    /// `remote_notification::factory::create_with_receiver`.
    pub transport: Arc<dyn PublishTransport>,
    /// The three collaborators one receiver runs against.
    pub runtime: ReceiverRuntime,
}

impl EventRelayPreparation {
    /// The receiver wiring this cell declared, if any.
    ///
    /// `None` on a cell with no `[plugins.remote.receiver]`, which is the state
    /// a `remote`-mode cell that only publishes is in.
    pub fn durable_receiver(&self) -> Option<DurableReceiverWiring> {
        self.receiver.clone()
    }
}

/// Prove the cell is fit to relay and build every input, spawning nothing.
///
/// Returns `Ok(None)` for every cell that has not enabled the relay. Any other
/// failure aborts startup: a relay that was asked for and could not be built
/// must not be silently absent, because a cell with no worker and a cell
/// perfectly caught up report the same empty backlog.
pub async fn prepare_event_relay(
    settings: &Settings,
    database_identity: Option<&DatabaseIdentity>,
    domain: Option<&Arc<DomainContext>>,
) -> Result<Option<EventRelayPreparation>> {
    let raw = match settings.outbox_relay.as_ref() {
        Some(raw) if raw.enabled => raw,
        // Absent and `enabled = false` are the same state. The receiver check
        // runs on the way out rather than being skipped: this is the one path
        // on which a declared receiver would otherwise vanish without a word.
        _ => {
            refuse_receiver_without_relay(settings)?;
            return Ok(None);
        }
    };

    let config = EventRelayConfig::from_settings(raw)
        .map_err(|error| anyhow!("Invalid [outbox_relay] configuration: {error}"))?;

    let mode = settings
        .notification
        .as_ref()
        .map_or("local", |ns| ns.mode.as_str());
    if mode != REMOTE_NOTIFICATION_MODE {
        return Err(anyhow!(StartupRefusal::NotificationModeNotRemote(
            mode.to_string()
        )));
    }

    // PIN(WP-119): cell identity from [plugins.remote_notification].cell_id.
    // The table's actual TOML name is `[plugins.remote]`, because the plugin's
    // registry name is `remote`; the producers lane reads the same value for
    // the `idempotency_key` preimage, so a cell cannot produce events under one
    // identity and relay them under another. A successful parse is what proves
    // the identity is present and matches the contract's grammar: `cell_id` is
    // a required, grammar-checked field there, so there is no second check
    // here that could disagree with it.
    let remote_table = settings
        .plugins
        .get(REMOTE_NOTIFICATION_MODE)
        .ok_or_else(|| {
            anyhow!(StartupRefusal::RemoteConfig(
                "the [plugins.remote] section is absent".to_string()
            ))
        })?;
    let remote = RemoteNotificationConfig::parse(remote_table)
        .map_err(|error| anyhow!(StartupRefusal::RemoteConfig(error.to_string())))?;

    let database_identity =
        database_identity.ok_or_else(|| anyhow!(StartupRefusal::NotPostgresMode))?;

    // Same refusal, one step further: the relay may not run without the
    // coordinator whose admission gate it feeds. An identity with no context
    // is unreachable today (a Postgres-mode cell that connects always builds
    // one), and checking it here is what keeps it unreachable — a reordering
    // that dropped the context would otherwise start a relay whose backpressure
    // silently reaches nothing.
    let domain = domain.ok_or_else(|| anyhow!(StartupRefusal::NotPostgresMode))?;

    let pool = build_relay_pool(settings)?;
    let state = startup::enforce_startup_preconditions_against_identity(&pool, database_identity)
        .await
        .map_err(|refusal| anyhow!(refusal))?;

    // The transport is built here rather than inside the client so its channel
    // is reachable: under the insecure test transport the receiver shares it,
    // because there is no client identity to separate. `connect_lazy` performs
    // no I/O, so a gateway that is down at boot does not stop a cell from
    // starting and serving storage.
    let grpc_transport = GrpcPublishTransport::connect_lazy(&remote).map_err(|error| {
        anyhow!("Failed to build the relay's private gateway transport: {error}")
    })?;
    let channel = grpc_transport.channel();
    let transport: Arc<dyn PublishTransport> = Arc::new(grpc_transport);
    let publisher: Arc<dyn DurablePublisher> = Arc::new(PrivateGatewayClient::with_transport(
        &remote,
        Arc::clone(&transport),
    ));

    // The receiver is built only when the cell declares one. `ReceiverRuntime`
    // is deliberately assembled here and nowhere else: the plugin factory
    // receives a `toml::Value` and cannot reach a Postgres pool, which is the
    // seam `receiver_store`'s module documentation describes.
    //
    // The target is `NoopInvalidationTarget`, and that is the correct target
    // rather than a placeholder: a `remote`-mode loreserver mounts no local
    // public notification service and keeps no repository-scoped cache this
    // plane feeds, so there is no process-local derived state to evict. When a
    // cell gains some, this one line is where its target is handed in.
    //
    // The receiver's channel is its OWN, under the `receiver`-role credential.
    // It is not the publisher's: the gateway maps one mTLS identity to one cell
    // and one role, `Consume` and `Ack` require `receiver`, and a `relay`
    // credential authenticates and is then refused as
    // `UNAUTHORIZED_RECEIVER_ROLE_V1` forever. `ReceiverConfig::mtls` is `None`
    // only under the insecure test transport, where the plugin presents no
    // client identity at all and one channel serves both.
    let receiver = match remote.receiver.as_ref() {
        None => None,
        Some(receiver_config) => {
            let receiver_channel = match receiver_config.mtls.as_ref() {
                None => channel,
                Some(mtls) => {
                    connect_gateway_channel(&remote.gateway_uri, Some(mtls)).map_err(|error| {
                        anyhow!("Failed to build the durable receiver's channel: {error}")
                    })?
                }
            };
            Some(DurableReceiverWiring {
                transport: Arc::clone(&transport),
                runtime: ReceiverRuntime {
                    store: Arc::new(PostgresReceiverStore::new(
                        pool.clone(),
                        remote.cell_id.clone(),
                    )),
                    stream: Arc::new(GrpcDurableStream::new(
                        receiver_channel,
                        remote.cell_id.clone(),
                    )),
                    target: Arc::new(NoopInvalidationTarget),
                },
            })
        }
    };

    let readiness = Arc::new(EventRelayReadiness::new(
        config.max_oldest_unpublished,
        config.readiness_probe_interval,
        config.publish_deadline,
    ));
    let admission = Arc::new(OutboxAdmission::new(pool.clone(), config.admission.clone()));

    let source = EnvelopeSource {
        cell_id: remote.cell_id.clone(),
        placement_epoch: remote.placement_epoch,
        producer_instance_id: remote.producer_instance_id.clone(),
    };

    info!(
        cell_id = %source.cell_id,
        relay_compat_floor = state.relay_compat_floor,
        owner = %config.owner,
        durable_receiver = receiver.is_some(),
        "CR-032 outbox relay enabled"
    );

    Ok(Some(EventRelayPreparation {
        pool,
        config,
        publisher,
        readiness,
        admission,
        domain: Arc::clone(domain),
        cell_id: remote.cell_id.clone(),
        source,
        receiver,
    }))
}

/// Attach the admission gate and start the relay's tasks.
///
/// `receiver_readiness` is the facet the notification plugin returned from
/// `factory::create_with_receiver`. It must be present exactly when
/// [`EventRelayPreparation::durable_receiver`] was, and the mismatch is an
/// error rather than a warning: a cell whose receiver runs but whose facet
/// reaches nothing would report `receiver_ready` absent while consuming, which
/// is the one reading this surface exists to make impossible.
///
/// # Errors
/// A wiring fault — the coordinator already carrying an admission gate, or the
/// receiver readiness disagreeing with the prepared runtime. Both abort
/// startup.
pub fn spawn_event_relay(
    prepared: EventRelayPreparation,
    receiver_readiness: Option<Arc<ReceiverReadiness>>,
    endpoints: &mut JoinSet<Result<()>>,
    shutdown: watch::Receiver<bool>,
) -> Result<EventRelayHandles> {
    let EventRelayPreparation {
        pool,
        config,
        publisher,
        readiness,
        admission,
        domain,
        cell_id,
        source,
        receiver,
    } = prepared;

    match (receiver.is_some(), receiver_readiness) {
        (true, Some(handle)) => readiness.attach_durable_receiver(handle).map_err(|_| {
            anyhow!("The relay readiness handle already carries a durable receiver facet")
        })?,
        (true, None) => {
            return Err(anyhow!(
                "this cell declares [plugins.remote.receiver] and a receiver runtime was built, \
                 but the notification plugin returned no readiness handle; the receiver did not \
                 start and the cell must not be treated as required-event ready"
            ));
        }
        (false, Some(_)) => {
            return Err(anyhow!(
                "a durable receiver readiness handle was supplied for a cell that declares no \
                 [plugins.remote.receiver]"
            ));
        }
        (false, None) => {}
    }

    let evaluator = ConsumerSafetyTask::new(
        pool.clone(),
        cell_id.clone(),
        config.readiness_probe_interval,
        readiness.clone(),
    );
    let reset_service = Arc::new(StreamResetHandler::new(pool.clone(), cell_id));

    // The gate is attached before the worker starts, so no window exists in
    // which the cell accepts required-event mutations against a relay that has
    // been declared healthy. Attaching twice is a wiring fault, not a
    // recoverable state: two gates over one cell would mean two caches and a
    // coin flip over which verdict a mutation reads.
    domain
        .attach_admission(admission.clone())
        .map_err(|_| anyhow!("The domain coordinator already carries an outbox admission gate"))?;

    let worker = EventRelayWorker::new(pool, publisher, config, readiness.clone(), source)
        .with_admission(admission.clone());
    lore_spawn!(endpoints, worker.run(shutdown.clone()));
    lore_spawn!(endpoints, evaluator.run(shutdown));

    Ok(EventRelayHandles {
        readiness,
        admission,
        reset_service,
    })
}

/// Refuse a `[plugins.remote.receiver]` declared on a cell with no relay.
///
/// Silent about everything else. A `[plugins.remote]` table that does not parse
/// is the plugin factory's refusal to report, with the offending field named;
/// duplicating that judgement here would give one misconfiguration two
/// different error messages depending on which section happened to be enabled.
fn refuse_receiver_without_relay(settings: &Settings) -> Result<()> {
    let mode = settings
        .notification
        .as_ref()
        .map_or("local", |ns| ns.mode.as_str());
    if mode != REMOTE_NOTIFICATION_MODE {
        return Ok(());
    }
    let Some(table) = settings.plugins.get(REMOTE_NOTIFICATION_MODE) else {
        return Ok(());
    };
    let Ok(remote) = RemoteNotificationConfig::parse(table) else {
        return Ok(());
    };
    if remote.receiver.is_some() {
        return Err(anyhow!(StartupRefusal::ReceiverWithoutRelay));
    }
    Ok(())
}

/// Build the relay's own small pool from the same `[plugins.postgres]`
/// connection shape the CR-007 stores use.
fn build_relay_pool(settings: &Settings) -> Result<Pool> {
    if settings.mutable_store.mode != POSTGRES_MODE {
        return Err(anyhow!(StartupRefusal::NotPostgresMode));
    }
    let config =
        resolve_plugin_config_with_fallback(&settings.plugins, POSTGRES_MODE, "mutable_store")
            .ok_or_else(|| {
                anyhow!(
                    "[outbox_relay] enabled requires a [plugins.postgres] section for the cell \
                     database"
                )
            })?;
    crate::plugins::postgres::connect_relay_pool(&config, RELAY_POOL_MAX)
        .map_err(|error| anyhow!("Failed to build the outbox relay pool: {error}"))
}

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
//! Only then is a pool built, a client connected, and a task spawned.

use std::sync::Arc;

use anyhow::Result;
use anyhow::anyhow;
use lore_base::lore_spawn;
use lore_postgres::domain::DatabaseIdentity;
use lore_postgres::pool::Pool;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::info;

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
use crate::plugins::remote_notification::PrivateGatewayClient;
use crate::plugins::remote_notification::RemoteNotificationConfig;
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
    /// TODO(WP-119 Phase 8): call `OutboxAdmission::check` before the
    /// transaction opens, at `lore-server/src/domain.rs`'s
    /// `DomainContext::admit` (reached through `admit_at_entry`), mapping a
    /// `Reject` verdict through
    /// `crate::event_relay::admission::rejection_status`. That file is the
    /// concurrent producers lane's for this round, so the handle is built,
    /// tested, and handed over rather than wired here.
    pub admission: Arc<OutboxAdmission>,
}

/// Build and spawn the relay, when this cell is configured to run one.
///
/// Returns `Ok(None)` for every cell that has not enabled it, which is all of
/// them today. Any other failure aborts startup: a relay that was asked for and
/// could not be built must not be silently absent, because a cell with no
/// worker and a cell perfectly caught up report the same empty backlog.
pub async fn configure_event_relay(
    settings: &Settings,
    database_identity: Option<&DatabaseIdentity>,
    endpoints: &mut JoinSet<Result<()>>,
    shutdown: watch::Receiver<bool>,
) -> Result<Option<EventRelayHandles>> {
    let Some(raw) = settings.outbox_relay.as_ref() else {
        return Ok(None);
    };
    if !raw.enabled {
        return Ok(None);
    }

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

    let pool = build_relay_pool(settings)?;
    let state = startup::enforce_startup_preconditions_against_identity(&pool, database_identity)
        .await
        .map_err(|refusal| anyhow!(refusal))?;

    let publisher: Arc<dyn DurablePublisher> =
        Arc::new(PrivateGatewayClient::connect(&remote).map_err(|error| {
            anyhow!("Failed to build the relay's private gateway client: {error}")
        })?);

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
        "CR-032 outbox relay enabled"
    );

    let evaluator = ConsumerSafetyTask::new(
        pool.clone(),
        remote.cell_id.clone(),
        config.readiness_probe_interval,
        readiness.clone(),
    );
    let reset_service = Arc::new(StreamResetHandler::new(
        pool.clone(),
        remote.cell_id.clone(),
    ));

    let worker = EventRelayWorker::new(pool, publisher, config, readiness.clone(), source);
    lore_spawn!(endpoints, worker.run(shutdown.clone()));
    lore_spawn!(endpoints, evaluator.run(shutdown));

    Ok(Some(EventRelayHandles {
        readiness,
        admission,
        reset_service,
    }))
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

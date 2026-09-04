// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The one shared backend both processes run on, and the authority every
//! assertion reads.
//!
//! Three distinct jobs live here and are worth keeping apart when reading:
//!
//! * **Bring-up.** Creating the domain, lock, and outbox schemas, arming the
//!   case's coordination path, and stamping the outbox cutover marker — all
//!   before either process starts, because the relay's startup gate is
//!   fail-closed on that marker and a first boot that had to create the schema
//!   could never also pass it.
//! * **Content fixture.** Writing revision content directly into the shared
//!   stores. `verify_fragments` requires every fragment of a pushed revision to
//!   already be present as a full context match
//!   (`lore-server/src/grpc/handlers/branch_push.rs:1154-1266`), so something
//!   has to put it there before the push. Doing it through `lore-postgres`'
//!   own stores writes exactly what a server writes, into the same bucket and
//!   the same `lore_fragments` rows both processes read.
//! * **Authority.** A third connection, owned by neither process, that every
//!   assertion goes through. Asking a server whether its own write landed is
//!   not a proof of anything; asking the database is.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::lore_spawn;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::backfill::BranchFacts;
use lore_postgres::domain::backfill::DomainBackfill;
use lore_postgres::domain::backfill::DomainBackfillSource;
use lore_postgres::domain::backfill::OrphanKey;
use lore_postgres::domain::backfill::RepositoryFacts;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::outbox::MembershipCas;
use lore_postgres::domain::outbox::membership::read_membership_state;
use lore_postgres::domain::outbox::membership::set_current_placement;
use lore_postgres::domain::outbox::stamp_cutover;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::immutable_store::ObjectStoreSettings;
use lore_postgres::store::immutable_store::PostgresImmutableStore;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_revision::branch;
use lore_revision::interface::ExecutionContext;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::node::Node;
use lore_revision::node::NodeFlags;
use lore_revision::node::ROOT_NODE;
use lore_revision::repository::RepositoryContext;
use lore_revision::state;
use lore_storage::hash::hash_string;
use tokio_postgres::Client;

use super::Arming;
use super::Env;

/// Pool size for every harness-owned pool.
///
/// Small on purpose. The two loreserver processes each open four pools against
/// this same database, and a harness that took a generous share would turn a
/// connection-budget problem into an unrelated-looking timeout.
const HARNESS_POOL_MAX: u32 = 4;

/// A backfill source for a database that has never held a repository.
///
/// Every case runs on a database the runner created moments earlier, so there
/// is genuinely nothing to project. Reporting that honestly is what lets the
/// cutover state machine run to completion; inventing rows would make the
/// backfill's own verification meaningless.
struct EmptyBackfillSource;

#[async_trait]
impl DomainBackfillSource for EmptyBackfillSource {
    async fn list_repositories(&self) -> Result<Vec<RepositoryFacts>, DomainError> {
        Ok(Vec::new())
    }

    async fn list_branches(&self, _repository_id: &[u8]) -> Result<Vec<BranchFacts>, DomainError> {
        Ok(Vec::new())
    }

    async fn snapshot_token(&self, _repository_id: &[u8]) -> Result<Vec<u8>, DomainError> {
        Ok(Vec::new())
    }

    async fn orphan_projection_keys(&self) -> Result<Vec<OrphanKey>, DomainError> {
        Ok(Vec::new())
    }
}

/// One outbox row, as the authority reports it.
#[derive(Debug, Clone)]
pub struct OutboxRow {
    pub event_id: uuid::Uuid,
    pub cell_id: String,
    pub event_kind: String,
    pub aggregate_kind: String,
    pub state: String,
    pub idempotency_key: Vec<u8>,
    pub attempt_count: i32,
    pub claim_owner: Option<String>,
    pub claim_generation: i64,
    /// When the current claim's lease runs out. `Some` means some worker holds
    /// this row and no other may take it until then.
    pub claim_expires_at: Option<std::time::SystemTime>,
    pub broker_sequence: Option<i64>,
    pub stream_identity: Option<String>,
}

/// The shared cell backend, plus the harness's authority connection.
pub struct SharedBackend {
    pub domain: Arc<PostgresDomainStore>,
    pub immutable: Arc<PostgresImmutableStore>,
    pub mutable: Arc<PostgresMutableStore>,
    pub execution: Arc<ExecutionContext>,
    pub cell_id: String,
    authority: Client,
}

impl SharedBackend {
    /// Create every schema, arm the case's path, and stamp the cutover marker.
    pub async fn open(env: &Env, arming: Arming) -> Self {
        let domain =
            PostgresDomainStore::connect(&env.pg_url, HARNESS_POOL_MAX, &TlsConfig::default())
                .await
                .unwrap_or_else(|error| {
                    panic!("create the domain schema on the case database: {error}")
                });
        let locks = domain.lock_coordinator();
        locks
            .bootstrap()
            .await
            .expect("bootstrap the SCHEMA-117 lock tables");

        // The CR-007 stores are opened HERE, before the backfill, and the order
        // is load-bearing rather than tidy. `DomainBackfill::verify` reads
        // `lore_mutable` to check no domain row lags its projection
        // (`lore-postgres/src/domain/backfill.rs:397-400`), and that table is
        // created by `PostgresMutableStore::connect`'s own `ensure_schema`.
        // Backfilling first fails with a bare `db error` that names neither the
        // table nor the ordering.
        let object = ObjectStoreSettings {
            bucket: env.s3_bucket.clone(),
            endpoint_url: Some(env.s3_endpoint.clone()),
            region: Some(env.s3_region.clone()),
            force_path_style: true,
            slow_operation_threshold_millis: 1_000,
            timeout_millis: 30_000,
            validate_bucket_on_startup: true,
        };
        let immutable = PostgresImmutableStore::connect(
            &env.pg_url,
            HARNESS_POOL_MAX,
            &TlsConfig::default(),
            object,
        )
        .await
        .unwrap_or_else(|error| panic!("open the harness immutable store: {error}"));
        let mutable =
            PostgresMutableStore::connect(&env.pg_url, HARNESS_POOL_MAX, &TlsConfig::default())
                .await
                .unwrap_or_else(|error| panic!("open the harness mutable store: {error}"));

        if arming == Arming::GovernedOutbox {
            // Domain enforcement first. `GovernedRepositoryCreate::prepare`
            // refuses outright on a cell that is not enforcing
            // (`lore-server/src/domain.rs:774-783`), so without this the
            // governed create every outbox case starts from is impossible —
            // and without a governed create there is no domain repository or
            // branch row for a governed push to find.
            //
            // The three steps are the real cutover state machine, not a
            // shortcut: run, verify, complete. On a fresh database the source
            // is empty, so each is trivially satisfied, but the state has to
            // pass through `BACKFILL_VERIFIED` and `BACKFILL_CUTOVER` for
            // `ready_for_enforcement` to hold, and `enable_enforcement`
            // re-checks that rather than trusting the caller.
            let source = EmptyBackfillSource;
            let backfill = DomainBackfill::for_store(&domain, &source);
            backfill
                .run()
                .await
                .expect("run the empty domain backfill on a fresh case database");
            let report = backfill
                .verify()
                .await
                .expect("verify the empty domain backfill");
            backfill
                .complete(&report)
                .await
                .expect("complete the domain backfill through cutover");
            domain
                .enable_enforcement()
                .await
                .expect("enable domain enforcement for this case");

            // An empty backfill on a fresh database is the whole cutover: there
            // are no legacy rows to convert, and the state machine still has to
            // pass through it before fencing may be armed.
            locks
                .backfill(&BTreeMap::new())
                .await
                .expect("run the empty lock backfill before cutover");
            // The production entry point refuses until WP-120's public mutation
            // contract exists. This bypass runs every schema, backfill,
            // quarantine, identity, and headroom check the real cutover runs,
            // and skips only that refusal; `wp117_push_witness_wiring.rs` pins
            // that no non-test source names it.
            locks
                .enable_fencing_for_component_fixture(false)
                .await
                .expect("arm fenced lock routing for this case");
        }

        let authority = raw_client(&env.pg_url).await;
        stamp_cutover(&authority, &env.cell_id)
            .await
            .expect("stamp the outbox cutover marker before either process boots");

        // The cell's AUTHORITATIVE placement. `stamp_cutover` seeds the
        // membership-state row with a NULL stream, and nothing inside
        // loreserver ever fills it in: which stream a cell consumes from is a
        // control-plane fact, and this harness is playing the control plane.
        //
        // It is stamped even for cases that run no receiver, because it costs
        // nothing and because a case that starts a receiver against an unset
        // placement waits forever on `no_current_placement` rather than failing
        // — the least debuggable shape available.
        //
        // All three values come from the runner, not from here. The gateway
        // derives the stream epoch from the JetStream stream's creation
        // timestamp and refuses a `Consume` that disagrees, so a constant in
        // this file would be wrong on every machine and silently so.
        let state = read_membership_state(&authority, &env.cell_id)
            .await
            .expect("read the outbox membership state")
            .expect("stamp_cutover seeds the membership-state row");
        match set_current_placement(
            &authority,
            &env.cell_id,
            &env.stream_identity,
            env.stream_epoch,
            env.placement_revision,
            state.membership_version,
        )
        .await
        .expect("stamp the cell's authoritative placement")
        {
            MembershipCas::Applied { .. } => {}
            other => panic!(
                "the placement stamp must apply on a fresh case database, got {other:?}; \
                 nothing else has written this cell's membership state yet"
            ),
        }

        Self {
            domain: Arc::new(domain),
            immutable: Arc::new(immutable),
            mutable: Arc::new(mutable),
            execution: crate::setup_execution("wp109-two-process-harness".to_owned()),
            cell_id: env.cell_id.clone(),
            authority,
        }
    }

    /// A repository context over the shared stores, for content fixtures.
    pub fn repository_context(&self, repository: RepositoryId) -> Arc<RepositoryContext> {
        Arc::new(RepositoryContext::new_server_context(
            self.immutable.clone(),
            self.mutable.clone(),
            repository,
        ))
    }

    /// Create a branch in the shared mutable store.
    ///
    /// `BranchPush` resolves the branch's metadata and its name mapping before
    /// it will accept anything, so a branch has to exist as real mutable-store
    /// state, not merely as an id the harness invented.
    pub async fn create_branch(&self, repository: RepositoryId, branch_id: BranchId, name: &str) {
        let context = self.repository_context(repository);
        let write_token = lore_server::grpc::get_write_token();
        Box::pin(LORE_CONTEXT.scope(self.execution.clone(), async move {
            branch::create(
                context,
                &write_token,
                branch_id,
                name,
                branch::default_category(),
                "wp109-harness",
                1,
                vec![],
                false,
                false,
            )
            .await
            .unwrap_or_else(|error| panic!("create branch {name}: {error:?}"));
        }))
        .await;
    }

    /// Serialize a revision whose parent is `parent`, returning its signature.
    ///
    /// `file_name` exists only to make two revisions with the same parent and
    /// the same revision number DIFFERENT. Content is content-addressed, so two
    /// empty revisions off one parent are the same revision, and a race between
    /// them would prove nothing: both writers would be pushing the same tip.
    /// The racing cases therefore give each candidate one distinctly named
    /// node; nothing else in this proof depends on a revision's contents.
    pub async fn serialize_revision(
        &self,
        repository: RepositoryId,
        parent: Hash,
        revision_number: u64,
        file_name: Option<&str>,
    ) -> Hash {
        let context = self.repository_context(repository);
        let write_token = lore_server::grpc::get_write_token();
        let file_name = file_name.map(str::to_owned);
        Box::pin(LORE_CONTEXT.scope(self.execution.clone(), async move {
            let state = state::State::new();
            state.set_parent_self(parent);
            state.set_revision_number(revision_number);
            if let Some(name) = file_name.as_deref() {
                let node = Node {
                    flags: NodeFlags::File.bits(),
                    name_hash: hash_string(name),
                    address: Address {
                        hash: Hash::default(),
                        context: Context::default(),
                    },
                    ..Default::default()
                };
                state
                    .node_add(context.clone(), ROOT_NODE, node, name)
                    .await
                    .expect("add a distinguishing node to the revision");
            }
            state
                .serialize(context, &write_token)
                .await
                .expect("serialize a revision into the shared immutable store")
        }))
        .await
    }

    // -- authority reads ---------------------------------------------------

    /// Every outbox row for this cell, oldest first.
    pub async fn outbox_rows(&self) -> Vec<OutboxRow> {
        let rows = self
            .authority
            .query(
                "SELECT event_id, cell_id, event_kind, aggregate_kind, state, idempotency_key, \
                        attempt_count, claim_owner, claim_generation, claim_expires_at, \
                        broker_sequence, stream_identity \
                   FROM lore_outbox_events WHERE cell_id = $1 ORDER BY created_at, event_id",
                &[&self.cell_id],
            )
            .await
            .expect("read the outbox");
        rows.into_iter()
            .map(|row| OutboxRow {
                event_id: row.get("event_id"),
                cell_id: row.get("cell_id"),
                event_kind: row.get("event_kind"),
                aggregate_kind: row.get("aggregate_kind"),
                state: row.get("state"),
                idempotency_key: row.get("idempotency_key"),
                attempt_count: row.get("attempt_count"),
                claim_owner: row.get("claim_owner"),
                claim_generation: row.get("claim_generation"),
                claim_expires_at: row.get("claim_expires_at"),
                broker_sequence: row.get("broker_sequence"),
                stream_identity: row.get("stream_identity"),
            })
            .collect()
    }

    /// Outbox rows of one kind.
    pub async fn outbox_rows_of_kind(&self, event_kind: &str) -> Vec<OutboxRow> {
        self.outbox_rows()
            .await
            .into_iter()
            .filter(|row| row.event_kind == event_kind)
            .collect()
    }

    /// Outbox rows this cell has not yet published.
    ///
    /// A governed repository create appends TWO rows of its own
    /// (`repository.published` and `branch.created`,
    /// `lore-server/src/domain.rs:811-830`), so a case that wants to arm a
    /// relay failpoint for one specific later row has to wait for those to
    /// drain first — otherwise the fault fires on the create's backlog and the
    /// case proves something other than what it says.
    pub async fn pending_count(&self) -> i64 {
        self.authority
            .query_one(
                "SELECT count(*)::bigint FROM lore_outbox_events \
                  WHERE cell_id = $1 AND state = 'pending'",
                &[&self.cell_id],
            )
            .await
            .expect("count pending outbox rows")
            .get(0)
    }

    /// Dead letters awaiting an operator disposition.
    pub async fn dead_letter_count(&self) -> i64 {
        self.authority
            .query_one(
                "SELECT count(*)::bigint FROM lore_outbox_dead_letters WHERE cell_id = $1",
                &[&self.cell_id],
            )
            .await
            .expect("count dead letters")
            .get(0)
    }

    /// The authoritative branch tip, read from the domain projection.
    pub async fn branch_latest_hash(&self, repository: &[u8], branch: &[u8]) -> Option<Vec<u8>> {
        self.authority
            .query_opt(
                "SELECT latest_hash FROM lore_domain_branches \
                  WHERE repository_id = $1 AND branch_id = $2",
                &[&repository, &branch],
            )
            .await
            .expect("read the domain branch projection")
            .map(|row| row.get("latest_hash"))
    }

    /// How many branch rows exist for `repository`, whatever their state.
    ///
    /// The "exactly one branch" half of the racing-push assertion: a race that
    /// produced two rows for one logical branch would be split-brain even if
    /// both carried the same tip.
    pub async fn branch_row_count(&self, repository: &[u8], branch: &[u8]) -> i64 {
        self.authority
            .query_one(
                "SELECT count(*)::bigint FROM lore_domain_branches \
                  WHERE repository_id = $1 AND branch_id = $2",
                &[&repository, &branch],
            )
            .await
            .expect("count domain branch rows")
            .get(0)
    }

    /// The generic mutable-store row count for one repository partition.
    ///
    /// Used for the legacy (ungoverned) path, where the domain projection is
    /// deliberately not written and `lore_mutable` is the authority.
    pub async fn mutable_key_count(&self, partition: &[u8]) -> i64 {
        self.authority
            .query_one(
                "SELECT count(*)::bigint FROM lore_mutable WHERE partition = $1",
                &[&partition],
            )
            .await
            .expect("count mutable-store keys")
            .get(0)
    }

    /// Lock rows held on one repository.
    pub async fn lock_owners(&self, repository: &[u8]) -> Vec<(Vec<u8>, String)> {
        self.authority
            .query(
                "SELECT hash, owner FROM lore_locks WHERE repository = $1 ORDER BY hash",
                &[&repository],
            )
            .await
            .expect("read lock rows")
            .into_iter()
            .map(|row| (row.get("hash"), row.get("owner")))
            .collect()
    }

    /// Fragment rows for one repository, by hash.
    pub async fn fragment_exists(&self, hash: &[u8], repository: &[u8]) -> bool {
        let count: i64 = self
            .authority
            .query_one(
                "SELECT count(*)::bigint FROM lore_fragments WHERE hash = $1 AND repository = $2",
                &[&hash, &repository],
            )
            .await
            .expect("read fragment rows")
            .get(0);
        count > 0
    }

    /// Whether the shared database no longer holds this fragment as readable.
    ///
    /// Written as a disjunction on purpose. An obliterate ends with the
    /// association gone AND the lifecycle row at `Obliterated`, but the two are
    /// separate writes and the store also has intermediate `Obliterating` and
    /// `PayloadDeleting` states (`FragmentState::bits`,
    /// `lore-postgres/src/store/immutable_store.rs:315-323`). Pinning one exact
    /// terminal shape would make this probe a test of the obliterate
    /// implementation's internals rather than of what the OTHER process can
    /// still read, which is the thing WP-109 cares about.
    ///
    /// An ABSENT lifecycle row counts as unreadable, which is only safe because
    /// a stored fragment always has one at `Stored` (`FragmentState::Stored`
    /// is `0`, written on every put). The caller therefore asserts the fragment
    /// exists BEFORE the obliterate, so "no row" here can only mean the row was
    /// removed and never that it was never written.
    pub async fn fragment_unreadable(&self, hash: &[u8], repository: &[u8]) -> bool {
        !self.fragment_exists(hash, repository).await
            || self
                .fragment_state(hash)
                .await
                .is_none_or(|state| state != 0)
    }

    /// The lifecycle state byte a fragment carries, if any.
    pub async fn fragment_state(&self, hash: &[u8]) -> Option<i64> {
        self.authority
            .query_opt(
                "SELECT state FROM lore_fragment_state WHERE hash = $1",
                &[&hash],
            )
            .await
            .expect("read fragment lifecycle state")
            .map(|row| row.get("state"))
    }

    /// Highest contiguous frontier any receiver has reported for this cell.
    ///
    /// `-1` when no checkpoint row exists at all, which is a different fact
    /// from a frontier of zero and must not be collapsed into one.
    pub async fn max_checkpoint_frontier(&self) -> i64 {
        let row = self
            .authority
            .query_one(
                "SELECT coalesce(max(contiguous_frontier), -1)::bigint \
                   FROM lore_outbox_checkpoints WHERE cell_id = $1",
                &[&self.cell_id],
            )
            .await
            .expect("read the checkpoint projection");
        row.get(0)
    }

    /// The frontier one receiver identity has reported, at its highest
    /// membership generation, with that generation.
    ///
    /// `None` when that receiver has reported no checkpoint at all, which is a
    /// different fact from a frontier of zero. Scoped to one receiver identity
    /// on purpose: with two processes consuming, a `max()` over the whole cell
    /// would let process A's progress satisfy an assertion about process B's.
    ///
    /// The highest generation, not every generation, because a restart
    /// allocates a new one and a stale predecessor's frontier says nothing
    /// about the receiver running now.
    pub async fn checkpoint_frontier_of(&self, receiver_identity: &str) -> Option<(i64, i64)> {
        self.authority
            .query_opt(
                "SELECT membership_generation, contiguous_frontier \
                   FROM lore_outbox_checkpoints \
                  WHERE cell_id = $1 AND receiver_identity = $2 \
                  ORDER BY membership_generation DESC LIMIT 1",
                &[&self.cell_id, &receiver_identity],
            )
            .await
            .expect("read the checkpoint projection for one receiver")
            .map(|row| {
                (
                    row.get("membership_generation"),
                    row.get("contiguous_frontier"),
                )
            })
    }

    /// The highest broker sequence this cell has been told a row was accepted
    /// at, or `None` when nothing has been accepted.
    ///
    /// The number a caught-up receiver's contiguous frontier has to reach. Read
    /// from the outbox rather than from either process, for the same reason
    /// every other assertion here is: a process reporting on its own progress
    /// is not authority for it.
    pub async fn max_broker_sequence(&self) -> Option<i64> {
        self.authority
            .query_one(
                "SELECT max(broker_sequence)::bigint FROM lore_outbox_events WHERE cell_id = $1",
                &[&self.cell_id],
            )
            .await
            .expect("read the highest accepted broker sequence")
            .get(0)
    }

    /// The cutover marker, proving the relay's startup gate had something to
    /// pass.
    pub async fn cutover_stamped(&self) -> bool {
        let row = self
            .authority
            .query_one(
                "SELECT cutover_at IS NOT NULL FROM lore_outbox_schema_state WHERE id = 1",
                &[],
            )
            .await
            .expect("read the outbox schema state");
        row.get(0)
    }

    /// Direct access for a bespoke assertion.
    pub fn authority(&self) -> &Client {
        &self.authority
    }
}

/// A raw connection whose driver task runs for the life of the case.
pub async fn raw_client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap_or_else(|error| panic!("open the harness authority connection: {error}"));
    lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("harness authority connection ended: {error}");
        }
    });
    client
}

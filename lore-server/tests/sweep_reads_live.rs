// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-120 refresh reads, against real Postgres: the authoritative generations
//! `RepositoryGet` and `BranchGet` attach to their responses.
//!
//! The READ side is the real `repository_get::handler` and `branch_get::handler`
//! over a real `PostgresMutableStore`, with the armed `DomainContext` the
//! server builds in postgres mode. The WRITE side is the governed domain
//! coordinator, called the way the governed handlers call it (a prepared
//! operation, the expected hashes, the committed projection). Each response
//! generation is compared with `lore_domain_repositories.generation` /
//! `lore_domain_branches.generation` read over a separate connection, so the
//! handler is never its own oracle.
//!
//! The lock-namespace half of the same contract lives with the other fenced
//! lock service cases in `p12_lock_service_fenced_routing.rs`
//! (`wp120_*` cases). `run-sweep-reads-live.ps1` runs both.

use std::sync::Arc;

use lore_base::types::Context;
use lore_base::types::KeyType;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::MetadataCasInput;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::store::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_proto::lore::repository::v1::RepositoryGetRequest;
use lore_proto::lore::repository::v1::RepositoryGetResponse;
use lore_proto::lore::repository::v1::repository_get_request::Query as RepositoryQuery;
use lore_proto::lore::revision::v1::BranchGetRequest;
use lore_proto::lore::revision::v1::BranchGetResponse;
use lore_proto::lore::revision::v1::branch_get_request::Query as BranchQuery;
use lore_revision::branch;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::domain::DomainContext;
use lore_server::grpc::repository::v1::repository_get;
use lore_server::grpc::revision::v1::branch_get;
use lore_storage::hash;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use tokio_postgres::Client;
use tonic::Code;
use tonic::Request;
use uuid::Uuid;

fn pg_url() -> String {
    std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; an unconfigured live case is NOT RUN")
}

async fn raw_client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("direct assertion client must connect");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

/// A prepared governed operation, as the governed handlers hold one.
async fn governed(store: &PostgresDomainStore, method: &str) -> GovernedOperation {
    let key = ReceiptKey {
        verified_issuer: format!(
            "https://issuer.example/wp120-sweep/{:016x}",
            rand::random::<u64>()
        ),
        authenticated_subject: "lorehub-control-plane".to_owned(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
        operation_id: Uuid::now_v7(),
    };
    let binding = OperationBinding {
        method: method.to_owned(),
        scope: key.tenant_scope_key.clone(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    };
    let witness = AuthorizationWitness {
        authorization_id: key.operation_id.as_bytes().to_vec(),
        authorization_revision: 7,
        verification_nonce: rand::random::<[u8; 32]>().to_vec(),
        bound_fields_digest: rand::random::<[u8; 32]>().to_vec(),
        consumed_ticket_sha256: rand::random::<[u8; 32]>().to_vec(),
        expected_claim_identity_digest: rand::random::<[u8; 32]>().to_vec(),
    };
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &binding, Some(&witness), None)
        .await
        .expect("prepare governed operation")
    else {
        panic!("an admissible operation must prepare");
    };
    GovernedOperation {
        key,
        binding,
        prepare_token: token,
    }
}

async fn repository_generation_row(db: &Client, repository_id: &[u8]) -> u64 {
    let generation: i64 = db
        .query_one(
            "SELECT generation FROM lore_domain_repositories WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .expect("read the repository generation row")
        .get(0);
    u64::try_from(generation).expect("non-negative generation")
}

async fn branch_generation_row(db: &Client, repository_id: &[u8], branch_id: &[u8]) -> u64 {
    let generation: i64 = db
        .query_one(
            "SELECT generation FROM lore_domain_branches \
              WHERE repository_id = $1 AND branch_id = $2",
            &[&repository_id, &branch_id],
        )
        .await
        .expect("read the branch generation row")
        .get(0);
    u64::try_from(generation).expect("non-negative generation")
}

/// Everything one case needs, with the domain rows and the legacy
/// `lore_mutable` records for one repository and its default branch.
struct Fixture {
    store: Arc<PostgresDomainStore>,
    domain: Arc<DomainContext>,
    unarmed_domain: Arc<DomainContext>,
    immutable: Arc<dyn lore_storage::ImmutableStore>,
    mutable: Arc<dyn lore_storage::MutableStore>,
    repository: Arc<RepositoryContext>,
    repository_id: RepositoryId,
    branch_id: BranchId,
    name: String,
    db: Client,
}

impl Fixture {
    /// Seed the legacy records the handlers read, then the domain rows
    /// (generation 1 each) for the same identities.
    async fn create() -> Self {
        let url = pg_url();
        let mutable: Arc<dyn lore_storage::MutableStore> = Arc::new(
            PostgresMutableStore::connect(&url, 4, &TlsConfig::default())
                .await
                .expect("real Postgres mutable store must connect"),
        );
        let immutable: Arc<dyn lore_storage::ImmutableStore> =
            lore_storage::local::immutable_store::create(
                None::<&str>,
                lore_storage::local::immutable_store::ImmutableStoreCreateOptions::none(),
                false,
                lore_storage::local::immutable_store::ImmutableStoreSettings::default(),
            )
            .await
            .expect("in-memory immutable store must construct");
        let store = Arc::new(
            PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
                .await
                .expect("real Postgres domain store must connect"),
        );
        // The lock schema installs the namespace trigger that
        // `branch_push_commit` revalidates against; install it before any
        // domain row exists.
        store
            .lock_coordinator()
            .bootstrap()
            .await
            .expect("install the lock schema before any domain row exists");
        let domain = Arc::new(DomainContext::new(
            store.clone() as Arc<dyn DomainTransactionStore>,
            true,
        ));
        let unarmed_domain = Arc::new(DomainContext::new(
            store.clone() as Arc<dyn DomainTransactionStore>,
            false,
        ));

        let repository_id: RepositoryId = rand::random();
        let branch_context: Context = Uuid::new_v4().into();
        let branch_id: BranchId = branch_context;
        let name = format!("wp120-sweep-{}", Uuid::new_v4());
        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable.clone(),
            mutable.clone(),
            repository_id,
        ));
        let metadata_hash = repository::metadata_store(
            repository.clone(),
            RepositoryMetadata {
                name: name.clone(),
                description: "version one".to_owned(),
                default_branch: branch_context,
                default_branch_name: "main".to_owned(),
                creator: "wp120".to_owned(),
                created: 1_700_000_000,
            },
        )
        .await
        .expect("seed repository metadata");
        let write_token = lore_server::grpc::get_write_token();
        branch::create(
            repository.clone(),
            &write_token,
            branch_id,
            "main",
            branch::default_category(),
            "wp120",
            1_700_000_000,
            Vec::new(),
            false,
            false,
        )
        .await
        .expect("seed the default branch");
        repository::metadata_store_hash(repository.clone(), metadata_hash)
            .await
            .expect("publish the repository metadata pointer");
        repository::store_name_to_id(repository.clone(), &name, repository_id)
            .await
            .expect("publish the name index");
        let branch_metadata_hash = branch::metadata_hash(repository.clone(), branch_id)
            .await
            .expect("read the seeded branch metadata pointer");

        let operation = governed(&store, "repository_create").await;
        let created = store
            .repository_create(
                &operation,
                &RepositoryCreateInput {
                    metadata_witnesses: Vec::new(),
                    repository_id: repository_id.data().to_vec(),
                    name: name.clone(),
                    metadata_hash: metadata_hash.as_ref().to_vec(),
                    default_branch_id: branch_id.data().to_vec(),
                    default_branch_name: "main".to_owned(),
                    default_branch_metadata_hash: branch_metadata_hash.as_ref().to_vec(),
                    default_branch_latest_hash: vec![0; 32],
                    creation_fingerprint: rand::random::<[u8; 32]>().to_vec(),
                    creation_fingerprint_version: 1,
                    projection: Vec::new(),
                    events: Vec::new(),
                },
            )
            .await
            .expect("create the domain rows");
        assert_eq!(created.outcome, DomainOutcome::Applied);

        let db = raw_client(&url).await;
        Self {
            store,
            domain,
            unarmed_domain,
            immutable,
            mutable,
            repository,
            repository_id,
            branch_id,
            name,
            db,
        }
    }

    async fn get_repository(
        &self,
        domain: Option<&Arc<DomainContext>>,
    ) -> Result<RepositoryGetResponse, tonic::Status> {
        repository_get::handler(
            Request::new(RepositoryGetRequest {
                query: Some(RepositoryQuery::Id(self.repository_id.into())),
            }),
            Arc::new(AllowAllRepositoryAuthorizer),
            self.immutable.clone(),
            self.mutable.clone(),
            &None,
            domain,
        )
        .await
        .map(tonic::Response::into_inner)
    }

    async fn get_branch(
        &self,
        query: BranchQuery,
        domain: Option<&Arc<DomainContext>>,
    ) -> Result<BranchGetResponse, tonic::Status> {
        let mut request = Request::new(BranchGetRequest { query: Some(query) });
        request.metadata_mut().insert_bin(
            REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(self.repository_id.data()),
        );
        branch_get::handler(
            request,
            self.immutable.clone(),
            self.mutable.clone(),
            &None,
            domain,
        )
        .await
        .map(tonic::Response::into_inner)
    }

    /// Repository generation as the handler reports it, checked against the
    /// table.
    async fn repository_generation(&self) -> u64 {
        let response = self
            .get_repository(Some(&self.domain))
            .await
            .expect("repository get must succeed");
        let reported = response
            .repository_generation
            .expect("an armed domain context must report the repository generation");
        assert_eq!(
            reported,
            repository_generation_row(&self.db, self.repository_id.data()).await,
            "the response must carry lore_domain_repositories.generation"
        );
        reported
    }

    /// Branch generation by id and by name, both checked against the table
    /// and against each other.
    async fn branch_generation(&self) -> u64 {
        let expected =
            branch_generation_row(&self.db, self.repository_id.data(), self.branch_id.data()).await;
        for query in [
            BranchQuery::Id(self.branch_id.into()),
            BranchQuery::Name("main".to_owned()),
        ] {
            let response = self
                .get_branch(query, Some(&self.domain))
                .await
                .expect("branch get must succeed");
            assert_eq!(
                response.branch_generation,
                Some(expected),
                "the response must carry lore_domain_branches.generation"
            );
        }
        expected
    }

    async fn repository_metadata_cas(&self, expected: Vec<u8>, new: Vec<u8>) {
        let operation = governed(&self.store, "metadata_compare_and_swap").await;
        let result = self
            .store
            .metadata_compare_and_swap(
                &operation,
                &MetadataCasInput {
                    repository_id: self.repository_id.data().to_vec(),
                    branch_id: None,
                    expected_hash: expected,
                    new_hash: new,
                    projection: Vec::new(),
                    event: None,
                },
            )
            .await
            .expect("repository metadata CAS must return");
        assert_eq!(result.outcome, DomainOutcome::Applied);
    }

    async fn branch_metadata_cas(&self, expected: Vec<u8>, new: Vec<u8>) {
        let operation = governed(&self.store, "metadata_compare_and_swap").await;
        let result = self
            .store
            .metadata_compare_and_swap(
                &operation,
                &MetadataCasInput {
                    repository_id: self.repository_id.data().to_vec(),
                    branch_id: Some(self.branch_id.data().to_vec()),
                    expected_hash: expected,
                    new_hash: new,
                    projection: Vec::new(),
                    event: None,
                },
            )
            .await
            .expect("branch metadata CAS must return");
        assert_eq!(result.outcome, DomainOutcome::Applied);
    }

    async fn push(&self, expected_latest: Vec<u8>, new_latest: Vec<u8>) {
        let operation = governed(&self.store, "branch_push_commit").await;
        let result = self
            .store
            .branch_push_commit(
                &operation,
                &BranchPushCommitInput {
                    fragment_witness: None,
                    repository_id: self.repository_id.data().to_vec(),
                    branch_id: self.branch_id.data().to_vec(),
                    expected_repository_generation: i64::try_from(
                        repository_generation_row(&self.db, self.repository_id.data()).await,
                    )
                    .expect("generation fits"),
                    expected_branch_generation: i64::try_from(
                        branch_generation_row(
                            &self.db,
                            self.repository_id.data(),
                            self.branch_id.data(),
                        )
                        .await,
                    )
                    .expect("generation fits"),
                    // The namespace trigger seeds both lock generations at 1
                    // and nothing in this case takes a lock.
                    expected_repository_lock_generation: 1,
                    expected_branch_lock_generation: 1,
                    expected_branch_lock_namespace_last_applied_fence: 0,
                    expected_latest_hash: expected_latest,
                    new_latest_hash: new_latest,
                    projection: Vec::new(),
                    event: None,
                },
            )
            .await
            .expect("branch push must return");
        assert_eq!(result.outcome, DomainOutcome::Applied);
    }

    async fn current_repository_metadata_hash(&self) -> Vec<u8> {
        self.db
            .query_one(
                "SELECT metadata_hash FROM lore_domain_repositories WHERE repository_id = $1",
                &[&self.repository_id.data().as_slice()],
            )
            .await
            .expect("read the repository metadata pointer")
            .get(0)
    }

    async fn current_branch_metadata_hash(&self) -> Vec<u8> {
        self.db
            .query_one(
                "SELECT metadata_hash FROM lore_domain_branches \
                  WHERE repository_id = $1 AND branch_id = $2",
                &[
                    &self.repository_id.data().as_slice(),
                    &self.branch_id.data().as_slice(),
                ],
            )
            .await
            .expect("read the branch metadata pointer")
            .get(0)
    }

    async fn current_branch_latest_hash(&self) -> Vec<u8> {
        self.db
            .query_one(
                "SELECT latest_hash FROM lore_domain_branches \
                  WHERE repository_id = $1 AND branch_id = $2",
                &[
                    &self.repository_id.data().as_slice(),
                    &self.branch_id.data().as_slice(),
                ],
            )
            .await
            .expect("read the branch latest pointer")
            .get(0)
    }
}

fn scoped<T>(future: impl std::future::Future<Output = T>) -> impl std::future::Future<Output = T> {
    let execution = lore_server::util::setup_execution(
        "wp120-sweep-reads-live",
        String::default(),
        String::default(),
    );
    lore_base::runtime::LORE_CONTEXT.scope(execution, future)
}

/// The repository generation is present on a read, equals the table, and
/// increases after a repository metadata CAS (and the response record shows
/// the change the generation announces).
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn wp120_repository_generation_is_read_and_increases_after_a_metadata_cas() {
    Box::pin(scoped(async {
        let fixture = Fixture::create().await;
        let first = fixture.repository_generation().await;
        assert_eq!(first, 1, "a fresh create commits generation 1");

        // The unarmed context and the absent context report nothing, and do
        // not even need the domain rows.
        let unarmed = fixture
            .get_repository(Some(&fixture.unarmed_domain))
            .await
            .expect("unarmed get");
        assert_eq!(unarmed.repository_generation, None);
        let none = fixture.get_repository(None).await.expect("no-domain get");
        assert_eq!(none.repository_generation, None);

        // Change the description through the legacy writers and move the
        // domain pointer with a governed CAS, as a metadata-set does.
        let old_hash = fixture.current_repository_metadata_hash().await;
        let new_hash = repository::metadata_store(
            fixture.repository.clone(),
            RepositoryMetadata {
                name: fixture.name.clone(),
                description: "version two".to_owned(),
                default_branch: fixture.branch_id,
                default_branch_name: "main".to_owned(),
                creator: "wp120".to_owned(),
                created: 1_700_000_000,
            },
        )
        .await
        .expect("store the second metadata blob");
        repository::metadata_store_hash(fixture.repository.clone(), new_hash)
            .await
            .expect("publish the second metadata pointer");
        fixture
            .repository_metadata_cas(old_hash, new_hash.as_ref().to_vec())
            .await;

        let second = fixture.repository_generation().await;
        assert!(
            second > first,
            "a metadata CAS must raise the repository generation: {first} -> {second}"
        );
        let response = fixture
            .get_repository(Some(&fixture.domain))
            .await
            .expect("repository get");
        assert_eq!(
            response.repository.expect("record").description,
            "version two"
        );
    }))
    .await;
}

/// The branch generation increases after a head-changing push and after
/// protect and unprotect, and does NOT change after a same-head push.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn wp120_branch_generation_increases_on_head_change_and_protection_only() {
    Box::pin(scoped(async {
        let fixture = Fixture::create().await;
        let created = fixture.branch_generation().await;
        assert_eq!(created, 1, "a fresh create commits branch generation 1");

        let unarmed = fixture
            .get_branch(
                BranchQuery::Id(fixture.branch_id.into()),
                Some(&fixture.unarmed_domain),
            )
            .await
            .expect("unarmed get");
        assert_eq!(unarmed.branch_generation, None);
        let none = fixture
            .get_branch(BranchQuery::Id(fixture.branch_id.into()), None)
            .await
            .expect("no-domain get");
        assert_eq!(none.branch_generation, None);

        // Head-changing push.
        let initial_head = fixture.current_branch_latest_hash().await;
        let new_head = rand::random::<[u8; 32]>().to_vec();
        fixture.push(initial_head, new_head.clone()).await;
        let after_push = fixture.branch_generation().await;
        assert!(
            after_push > created,
            "a head-changing push must raise the branch generation: {created} -> {after_push}"
        );

        // Same-head push: an idempotent success that changes nothing.
        fixture.push(new_head.clone(), new_head).await;
        let after_same_head = fixture.branch_generation().await;
        assert_eq!(
            after_same_head, after_push,
            "a same-head push must leave the branch generation unchanged"
        );

        // Protect, then unprotect: each is a branch metadata CAS.
        branch::protect(fixture.repository.clone(), fixture.branch_id)
            .await
            .expect("protect through the legacy writer");
        let protected_hash = branch::metadata_hash(fixture.repository.clone(), fixture.branch_id)
            .await
            .expect("protected metadata pointer");
        fixture
            .branch_metadata_cas(
                fixture.current_branch_metadata_hash().await,
                protected_hash.as_ref().to_vec(),
            )
            .await;
        let after_protect = fixture.branch_generation().await;
        assert!(
            after_protect > after_same_head,
            "protect must raise the branch generation: {after_same_head} -> {after_protect}"
        );
        let response = fixture
            .get_branch(
                BranchQuery::Id(fixture.branch_id.into()),
                Some(&fixture.domain),
            )
            .await
            .expect("branch get");
        assert!(response.branch.expect("record").protected);

        branch::unprotect(fixture.repository.clone(), fixture.branch_id)
            .await
            .expect("unprotect through the legacy writer");
        let unprotected_hash = branch::metadata_hash(fixture.repository.clone(), fixture.branch_id)
            .await
            .expect("unprotected metadata pointer");
        fixture
            .branch_metadata_cas(
                fixture.current_branch_metadata_hash().await,
                unprotected_hash.as_ref().to_vec(),
            )
            .await;
        let after_unprotect = fixture.branch_generation().await;
        assert!(
            after_unprotect > after_protect,
            "unprotect must raise the branch generation: {after_protect} -> {after_unprotect}"
        );
        let response = fixture
            .get_branch(
                BranchQuery::Id(fixture.branch_id.into()),
                Some(&fixture.domain),
            )
            .await
            .expect("branch get");
        assert!(!response.branch.expect("record").protected);
    }))
    .await;
}

/// A deleted repository answers `NotFound`; the generation never survives the
/// record it describes.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn wp120_a_deleted_repository_is_not_found() {
    Box::pin(scoped(async {
        let fixture = Fixture::create().await;
        assert_eq!(fixture.repository_generation().await, 1);

        // The governed delete tombstones the domain row and removes the
        // repository's metadata pointer in the same transaction.
        let operation = governed(&fixture.store, "repository_delete").await;
        let repository_hex = hex::encode(fixture.repository_id.data());
        let mut input = lore_postgres_delete_input(&fixture).await;
        input.projection = vec![ProjectionWrite {
            partition: fixture.repository_id.data().to_vec(),
            key_type: KeyType::RepositoryMetadata as i16,
            key: hash::hash_function_arg(
                fixture.repository.salt(),
                repository::METADATA,
                &repository_hex,
            )
            .as_ref()
            .to_vec(),
            value: None,
        }];
        let result = fixture
            .store
            .repository_delete(&operation, &input)
            .await
            .expect("repository delete must return");
        assert_eq!(result.outcome, DomainOutcome::Applied);

        for domain in [Some(&fixture.domain), None] {
            let error = fixture
                .get_repository(domain)
                .await
                .expect_err("a deleted repository must not be returned");
            assert_eq!(error.code(), Code::NotFound, "{error:?}");
        }
    }))
    .await;
}

/// The delete preflight the governed handler reads: the repository's name,
/// metadata pointer and live branches, straight from the domain rows.
async fn lore_postgres_delete_input(
    fixture: &Fixture,
) -> lore_postgres::domain::coordinator::RepositoryDeleteInput {
    let repository_id = fixture.repository_id.data().to_vec();
    let repository = fixture
        .db
        .query_one(
            "SELECT name, metadata_hash FROM lore_domain_repositories WHERE repository_id = $1",
            &[&repository_id],
        )
        .await
        .expect("read repository preflight");
    let branches = fixture
        .db
        .query(
            "SELECT branch_id, name, metadata_hash FROM lore_domain_branches \
              WHERE repository_id = $1 AND state = 0 ORDER BY branch_id",
            &[&repository_id],
        )
        .await
        .expect("read live branch preflight")
        .into_iter()
        .map(
            |row| lore_postgres::domain::coordinator::RepositoryDeleteBranchObservation {
                branch_id: row.get(0),
                name: row.get(1),
                metadata_hash: row.get(2),
            },
        )
        .collect();
    lore_postgres::domain::coordinator::RepositoryDeleteInput {
        repository_id,
        expected_generation: None,
        expected_name: repository.get(0),
        expected_metadata_hash: repository.get(1),
        branches,
        projection: Vec::new(),
        events: Vec::new(),
    }
}

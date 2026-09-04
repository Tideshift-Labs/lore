// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::sync::Arc;

use lore_base::types::KeyType;
use lore_postgres::domain::DomainOutcome;
use lore_postgres::domain::coordinator::ADMISSION_REJECTED_V1;
use lore_postgres::domain::coordinator::BranchDeleteInput;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_postgres::domain::store::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_revision::branch;
use lore_revision::lore::RepositoryId;
use lore_revision::metadata::Metadata;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::domain::AdmittedOperation;
use lore_server::domain::DomainContext;
use lore_server::domain::GovernedRepositoryCreate;
use lore_server::domain::GovernedScope;
use lore_server::domain::PLATFORM_METHOD_REPOSITORY_CREATE;
use lore_server::domain::PLATFORM_METHOD_REPOSITORY_OBLITERATE;
use lore_server::domain::RepositoryCreatePublication;
use lore_server::domain_intent::CanonicalIntent;
use lore_server::domain_intent::canonical_intent_digest;
use lore_server::grpc::domain_operation_metadata::DomainOperationMetadata;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_KEY;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
use lore_server::grpc::domain_operation_metadata::MEDIATED_SCOPE_KEY;
use lore_server::grpc::domain_operation_metadata::OPERATION_ID_KEY;
use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
use lore_server::grpc::domain_operation_metadata::scope_key_mediated_namespace;
use lore_storage::hash;
use tonic::metadata::BinaryMetadataValue;
use tonic::metadata::MetadataMap;
use uuid::Uuid;

fn service_token() -> AuthorizationToken {
    AuthorizationToken {
        issuer: "https://issuer.example/p12".to_string(),
        user_id: "lorehub-control-plane".to_string(),
        is_service_account: Some(true),
        ..Default::default()
    }
}

fn principal_namespace(user_id: Uuid) -> Vec<u8> {
    format!("principal-v1\0{user_id}").into_bytes()
}

fn mediated_key(operation_id: Uuid, org_uuid: &[u8; 16], principal: &[u8]) -> ReceiptKey {
    let token = service_token();
    ReceiptKey {
        verified_issuer: token.issuer,
        authenticated_subject: token.user_id,
        tenant_scope_key: scope_key_mediated_namespace(org_uuid, principal)
            .expect("fixture mediated namespace must be canonical"),
        operation_id,
    }
}

fn carriage(
    operation_id: Uuid,
    prepare_token: &[u8; 32],
    fingerprint: &[u8; 32],
    org_uuid: &[u8; 16],
    principal: &[u8],
) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert_bin(
        OPERATION_ID_KEY,
        BinaryMetadataValue::from_bytes(operation_id.as_bytes()),
    );
    let mut fingerprint_header = vec![FINGERPRINT_VERSION_V1];
    fingerprint_header.extend_from_slice(fingerprint);
    assert_eq!(fingerprint.len(), FINGERPRINT_V1_LEN);
    metadata.insert_bin(
        FINGERPRINT_KEY,
        BinaryMetadataValue::from_bytes(&fingerprint_header),
    );
    metadata.insert_bin(
        PREPARE_TOKEN_KEY,
        BinaryMetadataValue::from_bytes(prepare_token),
    );
    let mut mediated = Vec::with_capacity(66);
    mediated.push(1);
    mediated.extend_from_slice(org_uuid);
    mediated.extend_from_slice(principal);
    metadata.insert_bin(
        MEDIATED_SCOPE_KEY,
        BinaryMetadataValue::from_bytes(&mediated),
    );
    metadata
}

async fn create_repository(
    store: &Arc<dyn DomainTransactionStore>,
    repository_id: &[u8; 16],
    org_uuid: &[u8; 16],
    principal: &[u8],
) {
    let operation_id = Uuid::now_v7();
    let key = mediated_key(operation_id, org_uuid, principal);
    let fingerprint = rand::random::<[u8; 32]>().to_vec();
    let digest = canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
        repository_id,
        name: "p12-live",
        description: "",
        default_branch_id: Uuid::new_v4().as_bytes(),
        default_branch_name: "main",
        creator: None,
        caller_created: None,
    })
    .expect("fixture create intent must hash");
    let binding = OperationBinding {
        method: PLATFORM_METHOD_REPOSITORY_CREATE.to_string(),
        scope: key.tenant_scope_key.clone(),
        fingerprint_version: 1,
        fingerprint: fingerprint.clone(),
        canonical_intent_digest: digest,
    };
    let prepared = store
        .domain_operation_prepare(&key, &binding, None)
        .await
        .expect("fixture prepare must succeed");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("fixture create must prepare, got {prepared:?}");
    };
    let operation = GovernedOperation {
        key,
        binding,
        prepare_token: token,
    };
    let input = RepositoryCreateInput {
        repository_id: repository_id.to_vec(),
        name: format!("p12-live-{operation_id}"),
        metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_id: Uuid::new_v4().as_bytes().to_vec(),
        default_branch_name: "main".to_string(),
        default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_latest_hash: vec![0; 32],
        creation_fingerprint: fingerprint,
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        events: Vec::new(),
    };
    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("fixture repository create must execute");
    assert_eq!(result.outcome, DomainOutcome::Applied);
}

#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn exact_mediated_obliterate_consumes_while_tuple_tamper_preserves_prepared() {
    let url = std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; an unconfigured live case is NOT RUN");
    let store = Arc::new(
        PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
            .await
            .expect("real Postgres domain store must connect"),
    );
    let context = DomainContext::new(store, true);
    let store = context.store().clone();

    for tamper in [None, Some("org"), Some("principal")] {
        let repository_id = *Uuid::new_v4().as_bytes();
        let org_uuid = *Uuid::new_v4().as_bytes();
        let principal = principal_namespace(Uuid::new_v4());
        create_repository(&store, &repository_id, &org_uuid, &principal).await;
        let before = store
            .repository_snapshot(&repository_id)
            .await
            .expect("repository snapshot must read")
            .expect("fixture repository must exist");

        let operation_id = Uuid::now_v7();
        let fingerprint = rand::random::<[u8; 32]>();
        let address_hash = rand::random::<[u8; 32]>();
        let address_context = rand::random::<[u8; 16]>();
        let digest = canonical_intent_digest(&CanonicalIntent::Obliterate {
            repository_id: &repository_id,
            address_hash: &address_hash,
            address_context: &address_context,
        })
        .expect("obliterate intent must hash");
        let key = mediated_key(operation_id, &org_uuid, &principal);
        let binding = OperationBinding {
            method: PLATFORM_METHOD_REPOSITORY_OBLITERATE.to_string(),
            scope: key.tenant_scope_key.clone(),
            fingerprint_version: 1,
            fingerprint: fingerprint.to_vec(),
            canonical_intent_digest: digest.clone(),
        };
        let prepared = store
            .domain_operation_prepare(&key, &binding, None)
            .await
            .expect("obliterate prepare must succeed");
        let PrepareResult::Prepared { token, .. } = prepared else {
            panic!("obliterate must prepare, got {prepared:?}");
        };

        let mut carried_org = org_uuid;
        let mut carried_principal = principal.clone();
        if tamper == Some("org") {
            carried_org[0] ^= 0x01;
        } else if tamper == Some("principal") {
            carried_principal = principal_namespace(Uuid::new_v4());
        }
        let metadata = carriage(
            operation_id,
            &token,
            &fingerprint,
            &carried_org,
            &carried_principal,
        );
        let admitted = context
            .admit(
                &metadata,
                Some(&service_token()),
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect("canonical carriage must pass the entry gate")
            .expect("enforced carriage must govern");
        let operation = admitted.into_governed(PLATFORM_METHOD_REPOSITORY_OBLITERATE, digest);
        let result = store
            .begin_obliterate(&operation, &repository_id, None)
            .await
            .expect("obliterate coordinator call must return decisively");

        if tamper.is_none() {
            assert_eq!(result.outcome, DomainOutcome::Applied);
            assert!(matches!(
                store
                    .domain_operation_receipt_get(&key, &binding)
                    .await
                    .expect("committed receipt must read"),
                ReceiptLookup::Committed { .. }
            ));
        } else {
            assert!(matches!(
                result.outcome,
                DomainOutcome::NotApplied { ref reason, .. } if reason == ADMISSION_REJECTED_V1
            ));
            let after = store
                .repository_snapshot(&repository_id)
                .await
                .expect("repository snapshot must read")
                .expect("tamper must not remove the repository");
            assert_eq!(after.generation, before.generation);
            assert!(matches!(
                store
                    .domain_operation_receipt_get(&key, &binding)
                    .await
                    .expect("prepared receipt must read"),
                ReceiptLookup::Prepared { .. }
            ));
        }
    }
}

/// One `lore_mutable` row, for comparing the legacy and governed writers'
/// output exactly.
#[derive(Debug, PartialEq, Eq, Clone)]
struct MutableRow {
    partition: Vec<u8>,
    key_type: i16,
    key: Vec<u8>,
    value: Vec<u8>,
}

/// Every row under either partition, sorted for a stable comparison. Run
/// against a fresh, otherwise-empty database (this crate's live-test
/// convention), so `global_partition` returning exactly this test's own
/// repository-name-index row is a property of the fixture, not an assumption
/// this helper makes.
async fn mutable_rows(
    client: &tokio_postgres::Client,
    repository_partition: &[u8],
    global_partition: &[u8],
) -> Vec<MutableRow> {
    let mut rows: Vec<MutableRow> = client
        .query(
            "SELECT partition, key_type, key, value FROM lore_mutable \
             WHERE partition = $1 OR partition = $2",
            &[&repository_partition, &global_partition],
        )
        .await
        .expect("query lore_mutable rows")
        .into_iter()
        .map(|row| MutableRow {
            partition: row.get("partition"),
            key_type: row.get("key_type"),
            key: row.get("key"),
            value: row.get("value"),
        })
        .collect();
    rows.sort_by(|a, b| {
        (&a.partition, a.key_type, &a.key).cmp(&(&b.partition, b.key_type, &b.key))
    });
    rows
}

/// WP-116 Part 3 cold-review gap: nothing else asserts the five
/// `lore_mutable` projection rows a governed create writes
/// (`RepositoryCreatePublication::projection`, `lore-server/src/domain.rs`)
/// against what the four legacy writers actually leave in real Postgres. The
/// legacy path itself is not directly callable from here -- `repository_create`
/// (`lore-server/src/grpc/handlers/repository_create.rs`) is module-private --
/// so this test drives the same public `lore_revision::repository`/`branch`
/// primitives that private function calls, in the same order and with the
/// same arguments, as an independent oracle. That is not circular: the
/// property under test is agreement between two INDEPENDENT call chains
/// (`repository`/`branch`'s direct `store`/`compare_and_swap` writes versus
/// `RepositoryCreatePublication::projection`'s hand-rebuilt rows), not
/// agreement between this test and itself.
///
/// Both writers target the SAME repository id, name, branch id, branch name,
/// and content-derived metadata hashes, so `projection()`'s hash-derived keys
/// land on the exact same five rows the legacy writers already wrote. That
/// row set is captured once after the legacy write (the "before" snapshot,
/// asserted to be exactly five rows), then deleted from `lore_mutable`
/// directly -- the legacy writers never touch the domain tables, so this has
/// no effect on the governed create's own coordinator path -- and captured
/// again after the governed `commit()` call (the "after" snapshot). Deleting
/// between the two closes a vacuity hole an earlier revision of this test had
/// (INV, cold review 2026-09-03): landing on the same keys with the same
/// values also makes `after_rows == legacy_rows` hold if `projection()`
/// returned nothing at all, since a governed create that writes zero
/// projection rows simply leaves the pre-existing legacy rows untouched.
/// Deleting first means the "after" snapshot exists only if the governed path
/// actually recreated it. If `projection()` disagrees with the legacy writer
/// on any partition, key_type, key, or value -- most notably the
/// branch-latest row, which the legacy `compare_and_swap` writer leaves as an
/// explicit zero-valued row rather than deleting, unlike the other four
/// `store`-backed rows -- the second snapshot diverges from the first (or is
/// simply incomplete) and the comparison catches it. This is what a live
/// Postgres run and only a live Postgres run can prove: an offline test can
/// pin `projection()`'s own output but cannot prove it agrees with what the
/// real legacy `MutableStore` implementation actually persists.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn governed_create_projection_rows_match_the_legacy_writers_exactly() {
    let url = std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; an unconfigured live case is NOT RUN");

    let mutable_store: Arc<dyn lore_storage::MutableStore> = Arc::new(
        PostgresMutableStore::connect(&url, 4, &TlsConfig::default())
            .await
            .expect("real Postgres mutable store must connect"),
    );
    let immutable_store: Arc<dyn lore_storage::ImmutableStore> =
        lore_storage::local::immutable_store::create(
            None::<&str>,
            lore_storage::local::immutable_store::ImmutableStoreCreateOptions::none(),
            false,
            lore_storage::local::immutable_store::ImmutableStoreSettings::default(),
        )
        .await
        .expect("in-memory immutable store must construct");
    let (raw_client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("direct assertion client must connect");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });

    let repository_id: RepositoryId = rand::random();
    let name = format!("p12-live-proj-{}", Uuid::new_v4());
    let default_branch_id_context: lore_base::types::Context = Uuid::new_v4().into();
    let default_branch_id_bytes = *default_branch_id_context.data();
    let default_branch_name = "main";
    let creator = "p12-live-projection-tester";
    let created = 1_700_000_000u64;

    let execution = lore_server::util::setup_execution(
        "p12-live-projection",
        String::default(),
        String::default(),
    );
    lore_base::runtime::LORE_CONTEXT
        .scope(execution, async move {
            // --- Legacy write: the oracle. ---
            let legacy_repo = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                repository_id,
            ));
            let metadata = RepositoryMetadata {
                name: name.clone(),
                description: String::new(),
                default_branch: default_branch_id_context,
                default_branch_name: default_branch_name.to_string(),
                creator: creator.to_string(),
                created,
            };
            let metadata_hash = repository::metadata_store(legacy_repo.clone(), metadata)
                .await
                .expect("legacy metadata store");
            let write_token = lore_server::grpc::get_write_token();
            branch::create(
                legacy_repo.clone(),
                &write_token,
                default_branch_id_context,
                default_branch_name,
                branch::default_category(),
                creator,
                created,
                Vec::new(),
                false,
                false,
            )
            .await
            .expect("legacy branch create");
            repository::metadata_store_hash(legacy_repo.clone(), metadata_hash)
                .await
                .expect("legacy metadata pointer store");
            repository::store_name_to_id(legacy_repo.clone(), &name, repository_id)
                .await
                .expect("legacy name index store");

            let repository_partition = repository_id.data().to_vec();
            let global_partition = RepositoryId::default().data().to_vec();
            let legacy_rows =
                mutable_rows(&raw_client, &repository_partition, &global_partition).await;
            assert_eq!(
                legacy_rows.len(),
                5,
                "the legacy writers must leave exactly five lore_mutable rows, got {legacy_rows:?}"
            );

            // Delete the legacy rows before the governed write, so the
            // comparison below proves the governed create RECREATES exactly
            // these five rows, not merely that it leaves pre-existing ones
            // untouched. Without this, an empty `projection()` (writing
            // nothing at all) would pass the same `after_rows == legacy_rows`
            // assertion vacuously -- the legacy writers never touch the
            // domain tables, so deleting only their `lore_mutable` rows here
            // has no effect on the governed create's own coordinator path.
            for row in &legacy_rows {
                let deleted = raw_client
                    .execute(
                        "DELETE FROM lore_mutable WHERE partition = $1 AND key_type = $2 AND \
                         key = $3",
                        &[&row.partition, &row.key_type, &row.key],
                    )
                    .await
                    .expect("delete legacy row before governed write");
                assert_eq!(deleted, 1, "each legacy row must delete exactly once");
            }
            let cleared_rows =
                mutable_rows(&raw_client, &repository_partition, &global_partition).await;
            assert!(
                cleared_rows.is_empty(),
                "the five legacy rows must be gone before the governed write runs, got \
                 {cleared_rows:?}"
            );

            // --- Governed write: an independent path to the same rows. ---
            let mut branch_metadata = Metadata::new();
            branch::metadata_populate(
                &mut branch_metadata,
                default_branch_id_context,
                default_branch_name,
                branch::default_category(),
                creator,
                created,
                Vec::new(),
            )
            .expect("branch metadata populate");
            let branch_metadata_hash = branch_metadata
                .serialize(legacy_repo.clone())
                .await
                .expect("branch metadata serialize");

            let domain_store = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
                .await
                .expect("real Postgres domain store must connect");
            let domain = Arc::new(DomainContext::new(Arc::new(domain_store), true));
            let store = domain.store().clone();

            let operation_id = Uuid::now_v7();
            let key = ReceiptKey {
                verified_issuer: "https://issuer.example/p12-live-projection".to_string(),
                authenticated_subject: "p12-live-projection-tester".to_string(),
                tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
                operation_id,
            };
            let digest = canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
                repository_id: repository_id.data(),
                name: &name,
                description: "",
                default_branch_id: &default_branch_id_bytes,
                default_branch_name,
                creator: Some(creator),
                caller_created: Some(created),
            })
            .expect("create intent must hash");
            let binding = OperationBinding {
                method: PLATFORM_METHOD_REPOSITORY_CREATE.to_string(),
                scope: key.tenant_scope_key.clone(),
                fingerprint_version: 1,
                fingerprint: rand::random::<[u8; 32]>().to_vec(),
                canonical_intent_digest: digest.clone(),
            };
            let prepared = store
                .domain_operation_prepare(&key, &binding, None)
                .await
                .expect("prepare must succeed");
            let PrepareResult::Prepared { token, .. } = prepared else {
                panic!("must prepare, got {prepared:?}");
            };
            let admitted = AdmittedOperation {
                key: key.clone(),
                carried: DomainOperationMetadata {
                    operation_id,
                    fingerprint_version: 1,
                    fingerprint: binding.fingerprint.clone(),
                    prepare_token: token,
                    mediated_scope: None,
                    claim_witness: None,
                },
            };
            let governed = GovernedRepositoryCreate::prepare(Some(&domain), Some(admitted), digest)
                .expect("prepare must not error")
                .expect("enforcement is on; must admit");

            let default_branch_latest_hash = lore_storage::Hash::default();
            let publication = RepositoryCreatePublication {
                salt: legacy_repo.salt(),
                repository_id: repository_id.data(),
                name: &name,
                metadata_hash: metadata_hash.as_ref(),
                default_branch_id: &default_branch_id_bytes,
                default_branch_name,
                default_branch_metadata_hash: branch_metadata_hash.as_ref(),
                default_branch_latest_hash: default_branch_latest_hash.as_ref(),
            };
            governed
                .commit(&publication)
                .await
                .expect("governed create must succeed");

            let after_rows =
                mutable_rows(&raw_client, &repository_partition, &global_partition).await;
            assert_eq!(
                after_rows, legacy_rows,
                "the governed create's projection() must RECREATE byte-identical lore_mutable \
                 rows to the ones the legacy writers left (deleted above, so this proves the \
                 governed path actually wrote them, not merely that it left pre-existing rows \
                 untouched) -- same partition, key_type, key, and value for all five rows, \
                 including the branch-latest row's explicit zero value (a delete there would \
                 silently diverge from the legacy compare-and-swap writer's own contract)"
            );
        })
        .await;
}

/// Live-Postgres proof that the governed `branch_delete` COORDINATOR and the
/// REAL `lore_revision::branch::delete()` leave the SAME `lore_mutable`
/// end-state, compared against each other rather than against a hand-written
/// expectation: two identically-built sibling branches in one repository, one
/// deleted by each path.
///
/// # Bypassing the seam, deliberately -- this is NOT evidence branch delete is wired
///
/// `GovernedBranchDelete::commit()` is unconditionally refused on
/// `BranchDeleteProof::Unfrozen` -- there is no frozen CR-029 branch
/// tombstone-proof derivation yet (see `p12_tests.rs`'s own pin of that
/// refusal, and its OFFLINE pin of the private `projection()`'s key
/// derivation against a fixed test salt, since `projection()` is only
/// reachable from `p12_tests`, a child module of `domain.rs`). Neither
/// `commit()` nor the private `projection()` is reachable from this external
/// integration-test crate, so this test drives `store.branch_delete(...)`
/// (public, ungated) directly with 32 arbitrary proof bytes, exactly as
/// `domain_outbox_producers.rs`'s coordinator-level cases do. That proves
/// PROJECTION AGREEMENT ONLY: that a delete-shaped `ProjectionWrite` computed
/// the same way the seam's private `projection()` computes it removes the
/// same row a real legacy delete removes. It is not evidence the governed
/// path is reachable -- no caller can reach `GovernedBranchDelete::commit()`
/// today -- and no `repository_delete` analog exists in this file, for the
/// identical reason (`RepositoryDeleteProof::Unfrozen`).
///
/// # Non-vacuity
///
/// Both siblings' name rows are asserted PRESENT in `lore_mutable`
/// immediately before their respective delete. Without that assertion this
/// test would pass identically if the projection key targeted a row nothing
/// ever wrote -- a wrong salt, a missed case fold, or the wrong `KeyType` all
/// produce a plausible key for a row that does not exist, and a delete of an
/// absent key succeeds silently. The before-assertion is the test.
#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn branch_delete_governed_and_real_legacy_delete_agree_on_the_lore_mutable_end_state() {
    let url = std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; an unconfigured live case is NOT RUN");

    let mutable_store: Arc<dyn lore_storage::MutableStore> = Arc::new(
        PostgresMutableStore::connect(&url, 4, &TlsConfig::default())
            .await
            .expect("real Postgres mutable store must connect"),
    );
    let immutable_store: Arc<dyn lore_storage::ImmutableStore> =
        lore_storage::local::immutable_store::create(
            None::<&str>,
            lore_storage::local::immutable_store::ImmutableStoreCreateOptions::none(),
            false,
            lore_storage::local::immutable_store::ImmutableStoreSettings::default(),
        )
        .await
        .expect("in-memory immutable store must construct");
    let (raw_client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("direct assertion client must connect");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });

    let repository_id: RepositoryId = rand::random();
    let repository_partition = repository_id.data().to_vec();

    let execution = lore_server::util::setup_execution(
        "p12-live-branch-delete-agreement",
        String::default(),
        String::default(),
    );
    lore_base::runtime::LORE_CONTEXT
        .scope(execution, async move {
            let repo = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                repository_id,
            ));
            let write_token = lore_server::grpc::get_write_token();

            // One shared parent both siblings branch from. Ordinary sibling
            // shape, not special to this test -- an empty-stack root branch
            // plus one pushed revision, matching `branch_delete.rs`'s own
            // `create_test_branch` handler-test helper.
            let main = lore_base::types::Context::from(uuid::Uuid::now_v7());
            branch::create(
                repo.clone(),
                &write_token,
                main,
                branch::DEFAULT_DEFAULT_NAME,
                branch::default_category(),
                "p12-live-agreement-creator",
                1,
                Vec::new(),
                false,
                false,
            )
            .await
            .expect("main branch create");
            let state = Arc::new(lore_revision::state::State::new());
            state.set_parent_self(lore_base::types::Hash::default());
            state.set_revision_number(1);
            let state_hash = state
                .serialize(repo.clone(), &write_token)
                .await
                .expect("serialize main state");
            let head = lore_server::grpc::handlers::branch_push::push(
                repo.clone(),
                main,
                state_hash,
                true,
                true,
                false,
                branch::DEFAULT_HISTORY_STEP_SIZE,
                lore_server::grpc::server::RevisionListAcceleration::default(),
            )
            .await
            .expect("push main head")
            .revision;
            let branch_point = lore_base::types::BranchPoint {
                branch: main,
                revision: head,
            };

            // No repository metadata is ever written (no `repository::metadata_store`
            // call): `branch::delete()`'s modern default-branch check reads it and
            // silently skips on `Err`, falling through to the "old" stack-emptiness
            // check, which both siblings satisfy via `branch_point` above. Neither
            // sibling is ever protected or checked out as the current branch, so
            // `branch::delete()`'s other two preconditions never trigger either.
            // One shared build path for both siblings: the ONLY difference between
            // the two calls below is which id/name pair goes in, so a divergence
            // between the oracle and the governed side can only come from which
            // writer later deletes them, not from how they were built.
            async fn create_sibling_branch(
                repo: &Arc<RepositoryContext>,
                write_token: &lore_revision::repository::RepositoryWriteToken,
                branch_point: lore_base::types::BranchPoint,
                branch_id: lore_base::types::Context,
                name: &str,
            ) {
                branch::create(
                    repo.clone(),
                    write_token,
                    branch_id,
                    name,
                    branch::personal_category(),
                    "p12-live-agreement-creator",
                    2,
                    vec![branch_point],
                    false,
                    false,
                )
                .await
                .expect("sibling branch create");
            }

            let oracle_branch_id = lore_base::types::Context::from(uuid::Uuid::now_v7());
            let oracle_name = format!("wp119-branch-delete-oracle-{}", Uuid::new_v4());
            create_sibling_branch(
                &repo,
                &write_token,
                branch_point.clone(),
                oracle_branch_id,
                &oracle_name,
            )
            .await;

            let governed_branch_id = lore_base::types::Context::from(uuid::Uuid::now_v7());
            let governed_name = format!("wp119-branch-delete-governed-{}", Uuid::new_v4());
            create_sibling_branch(
                &repo,
                &write_token,
                branch_point,
                governed_branch_id,
                &governed_name,
            )
            .await;

            let name_key_type = KeyType::BranchId as i16;
            let oracle_name_key =
                hash::hash_function_arg(repo.salt(), branch::ID, &oracle_name.to_lowercase())
                    .as_ref()
                    .to_vec();
            let governed_name_key =
                hash::hash_function_arg(repo.salt(), branch::ID, &governed_name.to_lowercase())
                    .as_ref()
                    .to_vec();

            // --- Non-vacuity: both name rows must exist before either delete. ---
            let global_partition = RepositoryId::default().data().to_vec();
            let before_rows =
                mutable_rows(&raw_client, &repository_partition, &global_partition).await;
            assert!(
                before_rows
                    .iter()
                    .any(|row| row.key_type == name_key_type && row.key == oracle_name_key),
                "the real legacy writer must have left the oracle's name row before either \
                 delete runs, or the agreement proven below would be vacuous"
            );
            assert!(
                before_rows
                    .iter()
                    .any(|row| row.key_type == name_key_type && row.key == governed_name_key),
                "the real legacy writer must have left the governed sibling's name row before \
                 either delete runs, or the agreement proven below would be vacuous"
            );

            // --- Oracle: the real legacy delete. ---
            branch::delete(repo.clone(), oracle_branch_id)
                .await
                .expect("real legacy branch delete");

            // --- Governed: the coordinator, bypassing the fenced seam (see module
            // doc above). Needs its own domain rows; the legacy/oracle side above
            // needed none, since `lore_revision::branch` writes only `lore_mutable`.
            let domain_store = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
                .await
                .expect("real Postgres domain store must connect");
            // Installs SCHEMA-117 before any domain row exists: an after-insert
            // trigger on `lore_domain_branches` creates a lock-namespace row, and
            // that trigger requires the lock schema present even for this raw SQL
            // seed insert below (see `domain_outbox_producers.rs`'s `store()`).
            domain_store
                .lock_coordinator()
                .bootstrap()
                .await
                .expect("install SCHEMA-117 before any domain row exists");

            let default_branch_id = rand::random::<[u8; 16]>().to_vec();
            raw_client
                .execute(
                    "INSERT INTO lore_domain_repositories (
                        repository_id, state, generation, name, metadata_hash,
                        default_branch_id, creation_fingerprint_version,
                        creation_fingerprint, created_at
                    ) VALUES ($1, 0, 1, $2, $3, $4, 1, $5, clock_timestamp())",
                    &[
                        &repository_partition,
                        &format!("p12-live-branch-delete-{repository_id}"),
                        &rand::random::<[u8; 32]>().to_vec(),
                        // Deliberately NOT governed_branch_id, so this repository
                        // row's own default-branch recheck never refuses.
                        &default_branch_id,
                        &rand::random::<[u8; 32]>().to_vec(),
                    ],
                )
                .await
                .expect("seed the repository domain row");
            let governed_branch_id_bytes = *governed_branch_id.data();
            raw_client
                .execute(
                    "INSERT INTO lore_domain_branches (
                        repository_id, branch_id, repository_generation, state, generation,
                        name, metadata_hash, latest_hash, creation_fingerprint_version,
                        creation_fingerprint, delete_proof, created_at, deleted_at
                    ) VALUES ($1, $2, 1, 0, 1, $3, $4, $5, 1, $6, NULL, clock_timestamp(), NULL)",
                    &[
                        &repository_partition,
                        &governed_branch_id_bytes.to_vec(),
                        &governed_name,
                        &rand::random::<[u8; 32]>().to_vec(),
                        &rand::random::<[u8; 32]>().to_vec(),
                        &rand::random::<[u8; 32]>().to_vec(),
                    ],
                )
                .await
                .expect("seed the branch domain row");

            let operation_id = Uuid::now_v7();
            let key = ReceiptKey {
                verified_issuer: "https://issuer.example/p12-live-branch-delete".to_string(),
                authenticated_subject: "p12-live-branch-delete-tester".to_string(),
                tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
                operation_id,
            };
            let binding = OperationBinding {
                method: "branch_delete".to_string(),
                scope: key.tenant_scope_key.clone(),
                fingerprint_version: 1,
                fingerprint: rand::random::<[u8; 32]>().to_vec(),
                canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
            };
            let prepared = domain_store
                .domain_operation_prepare(&key, &binding, None)
                .await
                .expect("prepare must succeed");
            let PrepareResult::Prepared { token, .. } = prepared else {
                panic!("must prepare, got {prepared:?}");
            };
            let operation = GovernedOperation {
                key,
                binding,
                prepare_token: token,
            };

            // Hand-built to the same shape `BranchDeletePublication::projection()`
            // builds -- see the module doc above for why that private method
            // cannot be called directly from this crate -- using the same public
            // primitives (`hash::hash_function_arg`, `branch::ID`) computed above,
            // rather than trusting either side to grade itself.
            let input = BranchDeleteInput {
                repository_id: repository_partition.clone(),
                branch_id: governed_branch_id_bytes.to_vec(),
                expected_generation: None,
                delete_proof: rand::random::<[u8; 32]>().to_vec(),
                projection: vec![ProjectionWrite {
                    partition: repository_partition.clone(),
                    key_type: name_key_type,
                    key: governed_name_key.clone(),
                    value: None,
                }],
                events: Vec::new(),
            };
            let result = domain_store
                .branch_delete(&operation, &input)
                .await
                .expect("governed branch delete must succeed");
            assert_eq!(result.outcome, DomainOutcome::Applied);

            // --- Compare the two end states. ---
            let after_rows =
                mutable_rows(&raw_client, &repository_partition, &global_partition).await;

            assert!(
                !after_rows
                    .iter()
                    .any(|row| row.key_type == name_key_type && row.key == oracle_name_key),
                "the real legacy delete must have removed the oracle's own name row"
            );
            assert!(
                !after_rows
                    .iter()
                    .any(|row| row.key_type == name_key_type && row.key == governed_name_key),
                "the governed coordinator must have removed the governed sibling's own name row"
            );

            let oracle_metadata_key = branch::mutable_key(
                repo.salt(),
                branch::METADATA,
                repository_id,
                oracle_branch_id,
            )
            .0
            .as_ref()
            .to_vec();
            let oracle_latest_key =
                branch::mutable_key(repo.salt(), branch::LATEST, repository_id, oracle_branch_id)
                    .0
                    .as_ref()
                    .to_vec();
            let governed_metadata_key = branch::mutable_key(
                repo.salt(),
                branch::METADATA,
                repository_id,
                governed_branch_id,
            )
            .0
            .as_ref()
            .to_vec();
            let governed_latest_key = branch::mutable_key(
                repo.salt(),
                branch::LATEST,
                repository_id,
                governed_branch_id,
            )
            .0
            .as_ref()
            .to_vec();
            let value_of = |rows: &[MutableRow], key_type: i16, key: &[u8]| {
                rows.iter()
                    .find(|row| row.key_type == key_type && row.key == key)
                    .map(|row| row.value.clone())
            };
            for (label, key_type, key) in [
                (
                    "oracle metadata",
                    KeyType::BranchMetadata as i16,
                    oracle_metadata_key.as_slice(),
                ),
                (
                    "oracle latest",
                    KeyType::BranchLatestPointer as i16,
                    oracle_latest_key.as_slice(),
                ),
                (
                    "governed metadata",
                    KeyType::BranchMetadata as i16,
                    governed_metadata_key.as_slice(),
                ),
                (
                    "governed latest",
                    KeyType::BranchLatestPointer as i16,
                    governed_latest_key.as_slice(),
                ),
            ] {
                assert_eq!(
                    value_of(&before_rows, key_type, key),
                    value_of(&after_rows, key_type, key),
                    "{label} must survive its branch's delete unchanged on both sides -- \
                     BranchDeletePublication::projection() returns one row, not three, \
                     exactly because a branch delete leaves metadata/latest in place"
                );
                assert!(
                    value_of(&after_rows, key_type, key).is_some(),
                    "{label} must still be PRESENT after the delete, not merely unchanged \
                     relative to a possibly-absent before state"
                );
            }

            // Nothing else under this repository's partition moved: the only
            // difference between the two full row-sets is the two removed name
            // rows.
            let mut expected_after = before_rows.clone();
            expected_after.retain(|row| {
                !(row.key_type == name_key_type
                    && (row.key == oracle_name_key || row.key == governed_name_key))
            });
            assert_eq!(
                after_rows, expected_after,
                "the only rows to change between the two full snapshots must be the two \
                 removed name rows -- both sides must leave every other lore_mutable row \
                 (both branches' metadata/latest, and main's own rows) untouched"
            );
        })
        .await;
}

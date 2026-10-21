// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! A fragment list's address is the hash of its reference bytes, and a plain fragment's address is
//! the hash of its content, so plain bytes R and a list whose references are R share an address.
//! These tests pin how the put path and push verification refuse that swap, while honest uploads
//! of every shape still pass.

use std::sync::Arc;

use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_base::types::FragmentReference;
use lore_base::types::Hash;
use lore_revision::interface::ExecutionContext;
use lore_revision::lore::RepositoryId;
use lore_revision::node::Node;
use lore_revision::node::NodeFlags;
use lore_revision::node::ROOT_NODE;
use lore_revision::repository::RepositoryContext;
use lore_revision::state::State;
use lore_server::grpc::get_write_token;
use lore_server::grpc::handlers::branch_push::verify_fragments;
use lore_server::protocol::storage::messages::MessageHandleError;
use lore_server::protocol::storage::put::Put;
use lore_server::protocol::storage::put::handle_put;
use lore_storage::CompressionMode;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use lore_storage::compress;
use lore_storage::hash::hash_string;
use rand::random;
use tonic::Code;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

struct Fixture {
    store: Arc<dyn ImmutableStore>,
    mutable_store: Arc<dyn MutableStore>,
    execution: Arc<ExecutionContext>,
    repository: RepositoryId,
    context: Context,
}

impl Fixture {
    async fn new() -> Self {
        let (store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");
        Self {
            store,
            mutable_store,
            execution,
            repository: random(),
            context: random(),
        }
    }

    async fn submit(&self, put: &Put) -> Result<(), MessageHandleError> {
        handle_put(
            put,
            self.repository,
            "correlation".to_string(),
            "user".to_string(),
            self.store.clone(),
        )
        .await
        .map(|_| ())
    }

    fn address(&self, hash: Hash) -> Address {
        Address {
            hash,
            context: self.context,
        }
    }

    /// A plain fragment holding `content` as is.
    fn plain(&self, content: &[u8]) -> Put {
        Put {
            address: self.address(Hash::hash_buffer(content)),
            fragment: Fragment {
                flags: 0,
                size_payload: content.len() as u32,
                size_content: content.len() as u64,
            },
            payload: Some(Bytes::copy_from_slice(content)),
        }
    }

    /// A list over `leaves`, each covering its own content size, in order.
    fn list_over(&self, leaves: &[&Put]) -> Put {
        let mut offset = 0u64;
        let mut references = Vec::new();
        for leaf in leaves {
            references.push(FragmentReference {
                hash: leaf.address.hash,
                offset_content: offset,
            });
            offset += leaf.fragment.size_content;
        }
        self.list_of(&references, offset)
    }

    /// A list over `references` declaring `size_content`.
    fn list_of(&self, references: &[FragmentReference], size_content: u64) -> Put {
        let payload = Bytes::copy_from_slice(references.as_bytes());
        Put {
            address: self.address(Hash::hash_buffer(payload.as_ref())),
            fragment: Fragment {
                flags: FragmentFlags::PayloadFragmented.into(),
                size_payload: payload.len() as u32,
                size_content,
            },
            payload: Some(payload),
        }
    }

    /// The reference bytes of `list`, stored as a plain fragment under the list's own address.
    fn plain_copy_of(&self, list: &Put) -> Put {
        let bytes = list.payload.clone().expect("a list carries references");
        let copy = self.plain(bytes.as_ref());
        assert_eq!(
            copy.address, list.address,
            "plain bytes R share the list's address"
        );
        copy
    }

    fn leaf(&self, fill: u8, size: usize) -> Put {
        self.plain(&vec![fill; size])
    }

    fn repository_context(&self) -> Arc<RepositoryContext> {
        Arc::new(RepositoryContext::new_server_context(
            self.store.clone(),
            self.mutable_store.clone(),
            self.repository,
        ))
    }
}

async fn state_with_files(
    repository: &Arc<RepositoryContext>,
    files: &[(&str, Address, u64)],
) -> Arc<State> {
    let write_token = get_write_token();
    let state = Arc::new(State::new());
    // A file with no content, so even a state of "new" files has a stable anchor.
    let anchor = Node {
        flags: NodeFlags::File.bits(),
        name_hash: hash_string("anchor.txt"),
        ..Default::default()
    };
    state
        .node_add(repository.clone(), ROOT_NODE, anchor, "anchor.txt")
        .await
        .expect("add the anchor node");
    for (name, address, size) in files {
        let node = Node {
            flags: NodeFlags::File.bits(),
            name_hash: hash_string(name),
            address: *address,
            size: *size,
            ..Default::default()
        };
        state
            .node_add(repository.clone(), ROOT_NODE, node, name)
            .await
            .expect("add a file node");
    }
    let signature = state
        .serialize(repository.clone(), &write_token)
        .await
        .expect("serialize the state");
    State::deserialize(repository.clone(), signature)
        .await
        .expect("deserialize the state")
}

/// Run `verify_fragments` for a revision that adds `files` to an otherwise empty parent.
async fn verify_push(
    fixture: &Fixture,
    files: &[(&str, Address, u64)],
) -> Result<(), tonic::Status> {
    let execution = fixture.execution.clone();
    let repository = fixture.repository_context();
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let parent = state_with_files(&repository, &[]).await;
        let state = state_with_files(&repository, files).await;
        verify_fragments(repository, parent, None, state).await
    }))
    .await
}

fn assert_refused_as_invalid_argument(result: Result<(), tonic::Status>) {
    let status = result.expect_err("the push must be refused");
    assert_eq!(status.code(), Code::InvalidArgument, "{status:?}");
    assert!(
        status
            .message()
            .contains("Push names file content the store holds differently"),
        "{status:?}"
    );
}

fn assert_invalid_fragment(result: Result<(), MessageHandleError>) {
    assert!(
        matches!(result, Err(MessageHandleError::InvalidFragment)),
        "expected InvalidFragment, got {result:?}"
    );
}

mod swap {
    use super::*;

    /// The plain copy arrives before the children exist, which the put path cannot tell apart
    /// from an honest plain fragment. The honest list is then refused by the store, and a
    /// revision naming the real file size at the list address is refused at push verification.
    #[tokio::test]
    async fn poison_before_children_refuses_the_honest_list_and_the_push() {
        let fixture = Fixture::new().await;
        let leaves = [fixture.leaf(1, 100), fixture.leaf(2, 100)];
        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);
        let poison = fixture.plain_copy_of(&list);
        assert_eq!(list.fragment.size_content, 200);
        assert_eq!(poison.fragment.size_content, 80);

        fixture
            .submit(&poison)
            .await
            .expect("a plain copy before the children is the known race");
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("children are honest");
        }

        let honest = fixture.submit(&list).await;
        assert!(
            honest.is_err(),
            "the honest list must be refused over the poisoned address, got {honest:?}"
        );

        let address = fixture.address(list.address.hash);
        assert_refused_as_invalid_argument(
            verify_push(&fixture, &[("big.bin", address, 200)]).await,
        );
    }

    /// The client skips the upload because the server reports the hash present, so no list put
    /// ever reaches the store. Push verification is the only check left.
    #[tokio::test]
    async fn poison_with_the_upload_skipped_is_refused_at_push() {
        let fixture = Fixture::new().await;
        let leaves = [fixture.leaf(1, 100), fixture.leaf(2, 100)];
        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);

        fixture
            .submit(&fixture.plain_copy_of(&list))
            .await
            .expect("a plain copy before the children is the known race");
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("children are honest");
        }

        assert_refused_as_invalid_argument(
            verify_push(&fixture, &[("big.bin", list.address, 200)]).await,
        );
    }

    #[tokio::test]
    async fn poison_after_the_children_exist_is_refused_at_put() {
        let fixture = Fixture::new().await;
        let leaves = [fixture.leaf(1, 100), fixture.leaf(2, 100)];
        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("children are honest");
        }

        assert_invalid_fragment(fixture.submit(&fixture.plain_copy_of(&list)).await);
    }

    /// Both representations declare 80 bytes, so size cannot tell them apart; the structure bit
    /// has to. Plain copy first (children absent), then the honest list.
    #[tokio::test]
    async fn same_size_flip_plain_first_refuses_the_list() {
        let fixture = Fixture::new().await;
        let leaves = [fixture.leaf(1, 40), fixture.leaf(2, 40)];
        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);
        let poison = fixture.plain_copy_of(&list);
        assert_eq!(poison.fragment.size_content, list.fragment.size_content);

        fixture
            .submit(&poison)
            .await
            .expect("a plain copy before the children is the known race");
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("children are honest");
        }

        let honest = fixture.submit(&list).await;
        assert!(
            honest.is_err(),
            "the same-size list must be refused over the plain copy, got {honest:?}"
        );
    }

    /// The reverse order: the honest list is stored, then a plain copy of its reference bytes.
    #[tokio::test]
    async fn same_size_flip_list_first_refuses_the_plain_copy() {
        let fixture = Fixture::new().await;
        let leaves = [fixture.leaf(1, 40), fixture.leaf(2, 40)];
        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("children are honest");
        }
        fixture.submit(&list).await.expect("the honest list");

        assert!(
            fixture.submit(&fixture.plain_copy_of(&list)).await.is_err(),
            "a plain copy of a stored list's reference bytes must be refused"
        );
    }
}

mod list_structure {
    use super::*;

    #[tokio::test]
    async fn a_list_declaring_the_wrong_size_is_refused() {
        let fixture = Fixture::new().await;
        let leaves = [fixture.leaf(1, 100), fixture.leaf(2, 100)];
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("children are honest");
        }
        let honest = fixture.list_over(&[&leaves[0], &leaves[1]]);
        let references = honest.payload.clone().expect("references").to_vec();
        let references = references
            .chunks(size_of::<FragmentReference>())
            .map(|chunk| FragmentReference::read_from_bytes(chunk).expect("a whole reference"))
            .collect::<Vec<_>>();

        // Passes validate_fragment (the last offset is below the size) but covers 200 bytes.
        let lying = fixture.list_of(&references, 150);
        assert_invalid_fragment(fixture.submit(&lying).await);

        let larger = fixture.list_of(&references, 4096);
        assert_invalid_fragment(fixture.submit(&larger).await);

        fixture
            .submit(&honest)
            .await
            .expect("the honest size passes");
    }

    /// A push uploads a list and its children in parallel, so the last child may not have landed
    /// when the list arrives. Such a list is accepted; push verification checks it later.
    #[tokio::test]
    async fn a_list_whose_last_child_is_not_yet_stored_is_accepted() {
        let fixture = Fixture::new().await;
        let leaves = [fixture.leaf(1, 100), fixture.leaf(2, 100)];
        // Only the first child is stored.
        fixture.submit(&leaves[0]).await.expect("first child");

        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);
        fixture
            .submit(&list)
            .await
            .expect("a list ahead of its last child is accepted");

        fixture.submit(&leaves[1]).await.expect("last child");
        fixture
            .submit(&list)
            .await
            .expect("the same list passes once its last child exists");
    }

    /// The list arrives before every child, the children follow, and the honest push verifies.
    #[tokio::test]
    async fn a_list_put_before_its_children_verifies_once_they_arrive() {
        let fixture = Fixture::new().await;
        let leaves = [fixture.leaf(1, 100), fixture.leaf(2, 100)];
        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);

        fixture
            .submit(&list)
            .await
            .expect("a list ahead of all its children is accepted");
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("children follow");
        }

        verify_push(&fixture, &[("big.bin", list.address, 200)])
            .await
            .expect("the honest push verifies");
    }
    #[tokio::test]
    async fn an_honest_two_level_nested_list_passes() {
        let fixture = Fixture::new().await;
        let leaves = [
            fixture.leaf(1, 100),
            fixture.leaf(2, 100),
            fixture.leaf(3, 100),
            fixture.leaf(4, 100),
        ];
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("leaf");
        }
        let left = fixture.list_over(&[&leaves[0], &leaves[1]]);
        let right = fixture.list_over(&[&leaves[2], &leaves[3]]);
        fixture.submit(&left).await.expect("left list");
        fixture.submit(&right).await.expect("right list");

        let top = fixture.list_over(&[&left, &right]);
        assert_eq!(top.fragment.size_content, 400);
        fixture.submit(&top).await.expect("the nested list passes");
        fixture
            .submit(&top)
            .await
            .expect("the nested list is idempotent");
    }
}

mod honest_uploads {
    use super::*;

    #[tokio::test]
    async fn plain_uncompressed_passes_and_repeats() {
        let fixture = Fixture::new().await;
        let put = fixture.plain(&[9u8; 120]);
        for _ in 0..3 {
            fixture.submit(&put).await.expect("plain put");
        }
    }

    #[tokio::test]
    async fn plain_compressed_passes_and_repeats() {
        let fixture = Fixture::new().await;
        for mode in [CompressionMode::Lz4, CompressionMode::Zstd] {
            // 4000 bytes is a multiple of 40, so the list-shape probe really decodes it.
            let content = vec![b'a'; 4000];
            let plain = fixture.plain(&content);
            let (fragment, payload) =
                compress(plain.fragment, content.as_slice(), mode).expect("compress");
            assert_ne!(
                fragment.flags & FragmentFlags::PayloadCompressed,
                0,
                "{mode:?} must have compressed the content"
            );
            let put = Put {
                address: plain.address,
                fragment,
                payload: Some(payload),
            };
            for _ in 0..2 {
                fixture
                    .submit(&put)
                    .await
                    .unwrap_or_else(|error| panic!("{mode:?} put: {error:?}"));
            }
            fixture
                .submit(&plain)
                .await
                .expect("the uncompressed copy of the same content is accepted");
        }
    }

    #[tokio::test]
    async fn plain_content_shaped_like_a_list_over_absent_children_passes() {
        // Eighty bytes that parse as two increasing references, naming nothing stored.
        let fixture = Fixture::new().await;
        let references = [
            FragmentReference {
                hash: Hash::hash_buffer(b"nowhere-a"),
                offset_content: 0,
            },
            FragmentReference {
                hash: Hash::hash_buffer(b"nowhere-b"),
                offset_content: 40,
            },
        ];
        let put = fixture.plain(references.as_bytes());
        fixture
            .submit(&put)
            .await
            .expect("nothing it names is stored");
    }

    #[tokio::test]
    async fn a_list_repeats_idempotently() {
        let fixture = Fixture::new().await;
        let leaves = [fixture.leaf(1, 100), fixture.leaf(2, 100)];
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("leaf");
        }
        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);
        for _ in 0..3 {
            fixture.submit(&list).await.expect("list put");
        }
    }
}

mod push_verification {
    use super::*;

    #[tokio::test]
    async fn an_honest_plain_and_an_honest_list_file_pass() {
        let fixture = Fixture::new().await;
        let small = fixture.leaf(5, 100);
        fixture.submit(&small).await.expect("small file content");

        let leaves = [fixture.leaf(1, 100), fixture.leaf(2, 100)];
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("leaf");
        }
        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);
        fixture.submit(&list).await.expect("list");

        verify_push(
            &fixture,
            &[
                ("small.bin", small.address, 100),
                ("big.bin", list.address, 200),
            ],
        )
        .await
        .expect("sizes match the stored fragments");
    }

    #[tokio::test]
    async fn an_empty_file_with_the_zero_hash_is_not_compared() {
        let fixture = Fixture::new().await;
        verify_push(&fixture, &[("empty.txt", Address::default(), 0)])
            .await
            .expect("an empty file names no content");
    }

    #[tokio::test]
    async fn an_unchanged_file_still_passes() {
        let fixture = Fixture::new().await;
        let small = fixture.leaf(5, 100);
        fixture.submit(&small).await.expect("file content");
        let other = fixture.leaf(6, 50);
        fixture.submit(&other).await.expect("other content");

        let execution = fixture.execution.clone();
        let repository = fixture.repository_context();
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let parent = state_with_files(&repository, &[("kept.bin", small.address, 100)]).await;
            let state = state_with_files(
                &repository,
                &[
                    ("kept.bin", small.address, 100),
                    ("added.bin", other.address, 50),
                ],
            )
            .await;
            verify_fragments(repository, parent, None, state).await
        }))
        .await
        .expect("an unchanged file and an honest new one pass");
    }
}

mod nested_push_verification {
    use super::*;

    /// Three sub-lists of two 100-byte leaves each, under one top list covering 600 bytes.
    struct Nested {
        leaves: Vec<Put>,
        sublists: Vec<Put>,
        top: Put,
    }

    fn nested(fixture: &Fixture) -> Nested {
        let leaves: Vec<Put> = (1..=6).map(|fill| fixture.leaf(fill, 100)).collect();
        let sublists: Vec<Put> = leaves
            .chunks(2)
            .map(|pair| fixture.list_over(&[&pair[0], &pair[1]]))
            .collect();
        let top = fixture.list_over(&[&sublists[0], &sublists[1], &sublists[2]]);
        assert_eq!(top.fragment.size_content, 600);
        Nested {
            leaves,
            sublists,
            top,
        }
    }

    #[tokio::test]
    async fn an_honest_two_level_file_verifies() {
        let fixture = Fixture::new().await;
        let file = nested(&fixture);
        for put in file.leaves.iter().chain(&file.sublists) {
            fixture.submit(put).await.expect("leaf or sub-list");
        }
        fixture.submit(&file.top).await.expect("top list");

        verify_push(&fixture, &[("nested.bin", file.top.address, 600)])
            .await
            .expect("every level carries the size its parent implies");
    }

    /// A plain copy of the middle sub-list's reference bytes lands before its children, so the
    /// put path cannot tell it from honest content. The top list still passes its own put (its
    /// last child is honest), so only the recursive size check can refuse the push.
    #[tokio::test]
    async fn a_poisoned_middle_sub_list_fails_the_push() {
        let fixture = Fixture::new().await;
        let file = nested(&fixture);
        let middle = &file.sublists[1];

        fixture
            .submit(&fixture.plain_copy_of(middle))
            .await
            .expect("a plain copy before the children is the known race");
        for leaf in &file.leaves {
            fixture.submit(leaf).await.expect("leaf");
        }
        for sublist in [&file.sublists[0], &file.sublists[2]] {
            fixture.submit(sublist).await.expect("honest sub-list");
        }
        fixture.submit(&file.top).await.expect("top list");

        assert_refused_as_invalid_argument(
            verify_push(&fixture, &[("nested.bin", file.top.address, 600)]).await,
        );
    }
}
/// The same swap against the real Postgres store: the plain copy is accepted before the
/// children exist, the honest list is then refused by the store's compare-on-existing rule, and a
/// push that skipped the upload is refused by file-size verification because the Postgres store
/// reports the plain copy's size for the list address.
///
/// Needs a disposable Postgres and S3-compatible store; see
/// `lore-postgres/tests/immutable_store_representation.rs`. Fails loudly when the environment is
/// unset.
mod postgres_backed {
    use lore_postgres::store::immutable_store::ObjectStoreSettings;
    use lore_postgres::store::immutable_store::PostgresImmutableStore;

    use super::*;

    async fn postgres_fixture() -> Fixture {
        let var = |name: &str| {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("{name} must be set to run this ignored live test"))
        };
        let settings = ObjectStoreSettings {
            bucket: var("LORE_TEST_S3_BUCKET"),
            endpoint_url: Some(var("LORE_TEST_S3_ENDPOINT")),
            region: Some("us-east-1".to_string()),
            force_path_style: true,
            slow_operation_threshold_millis: u64::MAX,
            timeout_millis: 30_000,
            validate_bucket_on_startup: false,
        };
        let store = PostgresImmutableStore::connect(
            &var("LORE_TEST_PG_URL"),
            5,
            &lore_postgres::pool::TlsConfig::default(),
            settings,
        )
        .await
        .expect("connect the Postgres store");
        let mut fixture = Fixture::new().await;
        fixture.store = Arc::new(store);
        fixture
    }

    #[tokio::test]
    #[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
    async fn poison_before_children_is_refused_at_put_and_at_push() {
        let fixture = postgres_fixture().await;
        let leaves = [fixture.leaf(1, 100), fixture.leaf(2, 100)];
        let list = fixture.list_over(&[&leaves[0], &leaves[1]]);

        fixture
            .submit(&fixture.plain_copy_of(&list))
            .await
            .expect("a plain copy before the children is the known race");
        for leaf in &leaves {
            fixture.submit(leaf).await.expect("children are honest");
        }

        let honest = fixture.submit(&list).await;
        assert!(
            honest.is_err(),
            "the honest list must be refused over the poisoned address, got {honest:?}"
        );

        assert_refused_as_invalid_argument(
            verify_push(&fixture, &[("big.bin", list.address, 200)]).await,
        );
    }
}

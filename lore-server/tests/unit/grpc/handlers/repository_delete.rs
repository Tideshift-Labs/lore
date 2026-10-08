// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::RepositoryDeleteRequest;
use lore_revision::lore::RepositoryId;
use lore_server::grpc::handlers::repository_delete::*;
use lore_telemetry::InstrumentProvider;
use rand::random;
use tonic::Code;
use tonic::Request;

use crate::store::test_support::test_store_create;

struct TestInstrumentProvider;

impl InstrumentProvider for TestInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "test"
    }
}

fn make_request(repository_id: RepositoryId) -> Request<RepositoryDeleteRequest> {
    let id_bytes: Context = repository_id.into();
    Request::new(RepositoryDeleteRequest {
        id: bytes::Bytes::from(id_bytes),
    })
}

// TEST 3 (WP-116 guarded stop): confirms the ungoverned/legacy path at
// this fenced governed-mutation call site is not blocked by the CR-029
// gate. This file had NO test coverage of any kind before this addition.
// `admit_at_entry`'s own `Ok(None)` behavior is already pinned generically
// in `domain.rs`; this is the handler-specific companion. Narrow by
// design: a repository id that was never created only reaches the first
// statement of the legacy `repository_delete` logic (the
// `repository_query_id` lookup) before returning `NotFound` -- it does
// NOT exercise the rest of that function (name/metadata clearing, branch
// purge). `NotFound` is decisive proof the request got past the gate: a
// gate rejection here would be `Unimplemented` (an admitted-but-unwired
// operation) or `FailedPrecondition` (carriage supplied with no domain
// coordinator), never `NotFound`.
#[tokio::test]
async fn no_domain_coordinator_reaches_the_legacy_repository_lookup_not_blocked_by_the_gate() {
    let repository_id = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("test stores");

    let error = LORE_CONTEXT
        .scope(execution, async move {
            handler(
                make_request(repository_id),
                None, /* no auth_url */
                immutable_store,
                mutable_store,
                &TestInstrumentProvider,
                None, /* no domain coordinator */
            )
            .await
        })
        .await
        .expect_err("a never-created repository must be refused by the legacy delete logic");

    assert_eq!(error.code(), Code::NotFound);
    assert!(error.message().contains("Repository does not exist"));
}

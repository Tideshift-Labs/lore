// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! [CLIENT] WP-124: a managed `push_with_attempt_store` whose remote connect never finishes ends at
//! the managed bound with ffi code 28 (`Disconnected`), not -1 (`Internal`).
//!
//! This is the desktop's entry: `push_with_attempt_store` inside `with_managed_caller`. The push
//! awaits `RepositoryContext::remote()` in `lore`'s `push_impl_with_runner` before
//! `lore_revision`'s `push_with_runner` runs, so the not-sent marker must be converted there too.
//! The unit test in `lore-revision/tests/managed_remote_bound.rs` covers the inner path.
//!
//! The connect is held pending by a loopback TCP listener that accepts and never speaks, so the
//! gRPC handshake never completes. The fixture repository names an identity (`create_managed`):
//! without one, `load_and_connect` runs a blocking connect of its own to resolve it, and the
//! repository would never open. The bound comes from the process-wide
//! `LORE_QUIC_MANAGED_IDLE_TIMEOUT`, so this lives in its own binary.
#![allow(clippy::disallowed_methods)] // Fixture listener only.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use lore::interface::LoreEventCallback;
use lore_base::runtime::LORE_CONTEXT;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::interface::LoreString;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::fixture_execution_context;
use lore_transport::VolatileAttemptStore;
use lore_transport::attempt_store::AttemptStore;
use uuid::Uuid;

const BOUND_SECS: u64 = 1;
const BOUND: Duration = Duration::from_secs(BOUND_SECS);

/// Longer than any correct expiry: a missing bound must fail here, not hang the suite.
const HANG_GUARD: Duration = Duration::from_secs(20);

const FFI_DISCONNECTED: i32 = 28;

fn no_callback() -> LoreEventCallback {
    lore_revision::event::convert_event_callback(LoreEventCallbackConfig {
        user_context: 0,
        func: None,
    })
}

#[test]
fn a_managed_push_whose_connect_never_finishes_returns_disconnected_not_internal() {
    // SAFETY: the only test in this binary, and nothing has read the variable yet.
    unsafe {
        std::env::set_var("LORE_QUIC_MANAGED_IDLE_TIMEOUT", BOUND_SECS.to_string());
    }
    let runtime = lore::runtime();

    let status_and_elapsed = runtime.block_on(async {
        // Accepts every connection and holds it open without a byte.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding the silent listener");
        let address = listener.local_addr().expect("listener address");
        let holder = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let fixture = LORE_CONTEXT
            .scope(fixture_execution_context(), async {
                LiveRepository::create_managed(&format!("grpc://{address}")).await
            })
            .await;

        let attempts: Arc<dyn AttemptStore> = Arc::new(VolatileAttemptStore::new());
        let started = Instant::now();
        let status = tokio::time::timeout(
            HANG_GUARD,
            lore_transport::caller_operation::with_managed_caller(
                Uuid::new_v4(),
                attempts.clone(),
                Box::pin(lore::branch::push_with_attempt_store(
                    fixture.globals(),
                    lore::branch::LoreBranchPushArgs {
                        branch: LoreString::default(),
                        fast_forward_merge: 0,
                    },
                    no_callback(),
                    attempts,
                )),
            ),
        )
        .await
        .expect("a managed push never ended: the connect wait is unbounded");
        let elapsed = started.elapsed();
        holder.abort();
        drop(fixture);
        (status, elapsed)
    });
    let (status, elapsed) = status_and_elapsed;

    assert_eq!(
        status, FFI_DISCONNECTED,
        "expected Disconnected (28), not Internal (-1)"
    );
    assert!(
        elapsed >= BOUND - Duration::from_millis(200),
        "gave up before the bound: {elapsed:?}"
    );
    assert!(
        elapsed < BOUND + Duration::from_secs(8),
        "outlasted the bound: {elapsed:?}"
    );
}

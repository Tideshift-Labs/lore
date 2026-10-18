// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-120 strict caller admission with QUIC on, against a LIVE external cell.
//
// The in-process twin is `quic_strict_admission_test.rs`. This one dials a running loreserver
// replica (a Lorehub dev cell) instead, so it proves the deployed binary's wiring rather than a
// hand-built handler. It is `#[ignore]`d and reads its whole target from the environment:
//
//   LORE_G8_QUIC_URL        lore://<host>:<port>  one replica's public QUIC + gRPC port
//   LORE_G8_GRPC_URL        grpc://<host>:<port>  the gRPC leg for the managed write
//   LORE_G8_PARTITION       32 hex chars, the repository partition
//   LORE_G8_ACCESS_TOKEN    a read+write storage token for that partition
//   LORE_G8_IDENTITY_TOKEN  optional human authentication token
//
// Legs, each printed as one `G8-LEG {json}` line so a caller can record them separately:
//   managed-grpc-write    a Put inside a managed caller scope over gRPC is admitted
//   quic-read-undeclared  a stock QUIC Get of that fragment returns its bytes
//   quic-write-undeclared a stock QUIC Put is refused with storage status 200
//   quic-write-absent     the refused fragment cannot be read back
//
// Run: cargo test -p lore-integration-tests --features integration_tests --test integration --
//        --ignored --exact --nocapture
//        quic_strict_live_cell_probe_test::quic_strict_live_cell_probe_tests::live_strict_cell_keeps_quic_read_only
#[cfg(all(test, feature = "integration_tests"))]
mod quic_strict_live_cell_probe_tests {
    use std::error::Error;
    use std::str::FromStr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_revision::fragment;
    use lore_revision::lore::RepositoryId;
    use lore_transport::attempt_store::AttemptRecord;
    use lore_transport::attempt_store::AttemptResolution;
    use lore_transport::attempt_store::AttemptStore;
    use lore_transport::attempt_store::LockOwnership;
    use lore_transport::attempt_store::VolatileAttemptStore;
    use lore_transport::caller_operation::CallerOperationContext;
    use lore_transport::caller_operation::ManagedAttemptIntent;
    use lore_transport::caller_operation::with_caller_operation;
    use lore_transport::error::ProtocolError;
    use lore_transport::outcome::AttemptId;
    use rand::random;

    use crate::setup_execution;

    type TestResult = Result<(), Box<dyn Error>>;

    /// An in-memory journal that accepts managed intents. `VolatileAttemptStore` alone refuses
    /// them (a legacy journal must not implicitly promise managed recovery).
    #[derive(Default)]
    struct ManagedJournal {
        inner: VolatileAttemptStore,
    }

    #[async_trait]
    impl AttemptStore for ManagedJournal {
        async fn record_managed(
            &self,
            record: &AttemptRecord,
            _intent: &ManagedAttemptIntent,
        ) -> Result<(), ProtocolError> {
            self.inner.record(record).await
        }
        async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
            self.inner.record(record).await
        }
        async fn lookup(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
            self.inner.lookup(id).await
        }
        async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
            self.inner.unresolved().await
        }
        async fn record_ownership(&self, ownership: &LockOwnership) -> Result<(), ProtocolError> {
            self.inner.record_ownership(ownership).await
        }
        async fn ownership_for(
            &self,
            branch: &Context,
            resource_hash: &Hash,
        ) -> Result<Option<LockOwnership>, ProtocolError> {
            self.inner.ownership_for(branch, resource_hash).await
        }
        async fn clear_ownership(
            &self,
            branch: &Context,
            resource_hash: &Hash,
        ) -> Result<(), ProtocolError> {
            self.inner.clear_ownership(branch, resource_hash).await
        }
        async fn resolve(
            &self,
            id: &AttemptId,
            resolution: AttemptResolution,
        ) -> Result<(), ProtocolError> {
            self.inner.resolve(id, resolution).await
        }
    }

    fn required(name: &str) -> Result<String, Box<dyn Error>> {
        std::env::var(name)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{name} is not set; this probe needs a live cell").into())
    }

    fn leg(name: &str, pass: bool, detail: &str) {
        println!(
            "G8-LEG {}",
            serde_json::json!({ "leg": name, "result": if pass { "pass" } else { "fail" }, "detail": detail })
        );
    }

    async fn session(
        url: &str,
        partition: RepositoryId,
        identity_token: &str,
        access_token: &str,
    ) -> Result<Arc<lore_transport::session::StorageSession>, ProtocolError> {
        // Unique per call: the transport's connection cache is process-global and keyed by url
        // plus identity.
        let identity = format!("g8-live-probe-{}", random::<u32>());
        let connection =
            lore_transport::connect(url, &identity, partition, 1, identity_token, access_token)
                .await?;
        connection.session(partition, "g8-live-probe").await
    }

    #[tokio::test]
    #[ignore = "needs a live strict QUIC-on cell; driven by lorehub's dev-cell-admission-probe"]
    async fn live_strict_cell_keeps_quic_read_only() -> TestResult {
        let quic_url = required("LORE_G8_QUIC_URL")?;
        let grpc_url = required("LORE_G8_GRPC_URL")?;
        let partition = RepositoryId::from_str(&required("LORE_G8_PARTITION")?)
            .map_err(|error| format!("LORE_G8_PARTITION is not a partition: {error:?}"))?;
        let access = required("LORE_G8_ACCESS_TOKEN")?;
        let identity = std::env::var("LORE_G8_IDENTITY_TOKEN").unwrap_or_default();
        let execution = setup_execution("g8-live-probe".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let mut failures = Vec::new();

                // 1. A managed gRPC Put is admitted.
                let grpc = session(&grpc_url, partition, &identity, &access).await?;
                let (seeded, seeded_address, seeded_payload) = fragment::generate_random();
                let context = CallerOperationContext::new(
                    uuid::Uuid::now_v7(),
                    partition,
                    Arc::new(ManagedJournal::default()),
                );
                let managed = with_caller_operation(
                    context,
                    grpc.put(seeded_address, seeded, Some(seeded_payload.clone())),
                )
                .await;
                leg(
                    "managed-grpc-write",
                    managed.is_ok(),
                    &format!("{managed:?} address={seeded_address}"),
                );
                if managed.is_err() {
                    failures.push("managed-grpc-write");
                }

                // 2. A stock QUIC Get of that fragment returns its bytes.
                let quic = session(&quic_url, partition, &identity, &access).await?;
                let read = quic.get(&seeded_address).await;
                let read_ok = matches!(&read, Ok((_, payload)) if *payload == seeded_payload);
                leg(
                    "quic-read-undeclared",
                    read_ok,
                    &match &read {
                        Ok((_, payload)) => format!("Ok({} bytes)", payload.len()),
                        Err(error) => format!("Err({error:?})"),
                    },
                );
                if !read_ok {
                    failures.push("quic-read-undeclared");
                }

                // 3. A stock QUIC Put is refused with storage status 200 (unsupported-client).
                let (refused, refused_address, refused_payload) = fragment::generate_random();
                let write = quic
                    .put(refused_address, refused, Some(refused_payload))
                    .await;
                let detail = match &write {
                    Ok(()) => "Ok(()) stored".to_string(),
                    Err(error) => format!("{error:?} | {error}"),
                };
                let refused_200 = match &write {
                    Ok(()) => false,
                    // The client renders a QUIC storage status as "error code <n>".
                    Err(error) => {
                        !error.is_outcome_unknown() && error.to_string().ends_with("error code 200")
                    }
                };
                leg(
                    "quic-write-undeclared",
                    refused_200,
                    &format!("{detail} address={refused_address}"),
                );
                if !refused_200 {
                    failures.push("quic-write-undeclared");
                }

                // 4. The refused fragment is absent: a read of it answers NotFound. Any other
                // error (auth, transport, server failure) proves nothing about absence.
                let absent = quic.get(&refused_address).await;
                let not_found = matches!(&absent, Err(ProtocolError::NotFound(_)));
                leg(
                    "quic-write-absent",
                    not_found,
                    &match &absent {
                        Ok((_, payload)) => format!("Ok({} bytes) PRESENT", payload.len()),
                        Err(error) => format!("Err({error:?})"),
                    },
                );
                if !not_found {
                    failures.push("quic-write-absent");
                }

                if failures.is_empty() {
                    Ok(())
                } else {
                    Err(format!("legs failed: {}", failures.join(", ")).into())
                }
            })
            .await
    }
}

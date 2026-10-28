// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-120 strict caller admission with QUIC on, and WP-124 declared managed writes over QUIC,
// against a LIVE external cell.
//
// The in-process twin is `quic_strict_admission_test.rs`. This one dials a running loreserver
// replica (a Lorehub dev cell) instead, so it proves the deployed binary's wiring rather than a
// hand-built handler. Both tests are `#[ignore]`d and read their whole target from the
// environment:
//
//   LORE_G8_QUIC_URL        lore://<host>:<port>  one replica's public QUIC + gRPC port
//   LORE_G8_GRPC_URL        grpc://<host>:<port>  the gRPC leg for the managed gRPC write
//   LORE_G8_PARTITION       32 hex chars, the repository partition
//   LORE_G8_ACCESS_TOKEN    a read+write storage token for that partition
//   LORE_G8_IDENTITY_TOKEN  optional human authentication token
//
// `live_strict_cell_admits_only_declared_quic_writes` legs, in order, each printed as one
// `G8-LEG {json}` line so a caller can record them separately:
//   managed-grpc-write     a Put inside a managed caller scope over gRPC is admitted
//   quic-read-undeclared   a stock QUIC Get of that fragment returns its bytes
//   quic-write-undeclared  a stock QUIC Put is refused with storage status 200
//   quic-write-absent      the refused fragment cannot be read back
//   managed-quic-write     a Put inside a managed caller scope over QUIC is admitted, and the scope
//                          recorded one declared QUIC session (`declared_session_count() == 1`)
//   managed-quic-read-back a QUIC Get, on a fresh connection, returns the managed write's bytes
// The test fails unless every leg above was recorded, so a leg that did not run can never read as a
// pass. A leg that cannot run because an earlier step errored out fails the test with that error
// and prints no line for itself; the caller treats a missing `G8-LEG` line as not run (exit 2).
//
// What the `managed-quic-write` witness is, and is not: the scope's declared-session count is
// recorded by the client transport when a QUIC declared `AuthorizeStart` (action 2) is sent and
// stays 0 for gRPC storage (pinned in `quic_declared_session_test.rs`). It proves the client sent
// the write on a declared QUIC session. The server's own session table is not visible from outside
// a live cell, so "the server held a declared session" is shown only by the write being admitted
// by a strict cell that refuses the same Put undeclared (`quic-write-undeclared`).
//
// `live_declared_session_cost` measures what a declared session costs a caller, one `G8-COST`
// line per series (see its doc comment).
//
// Run: cargo test -p lore-integration-tests --features integration_tests --test integration --
//        --ignored --exact --nocapture
//        quic_strict_live_cell_probe_test::quic_strict_live_cell_probe_tests::live_strict_cell_admits_only_declared_quic_writes
// and, for the cost series, the same command with
//        quic_strict_live_cell_probe_test::quic_strict_live_cell_probe_tests::live_declared_session_cost
#[cfg(all(test, feature = "integration_tests"))]
mod quic_strict_live_cell_probe_tests {
    use std::error::Error;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

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

    /// The legs `live_strict_cell_admits_only_declared_quic_writes` must record, in order.
    const EXPECTED_LEGS: [&str; 6] = [
        "managed-grpc-write",
        "quic-read-undeclared",
        "quic-write-undeclared",
        "quic-write-absent",
        "managed-quic-write",
        "managed-quic-read-back",
    ];

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

    /// The live cell's target, read from the environment.
    struct LiveCell {
        quic_url: String,
        grpc_url: String,
        partition: RepositoryId,
        access: String,
        identity: String,
    }

    impl LiveCell {
        fn from_env() -> Result<Self, Box<dyn Error>> {
            Ok(Self {
                quic_url: required("LORE_G8_QUIC_URL")?,
                grpc_url: required("LORE_G8_GRPC_URL")?,
                partition: RepositoryId::from_str(&required("LORE_G8_PARTITION")?)
                    .map_err(|error| format!("LORE_G8_PARTITION is not a partition: {error:?}"))?,
                access: required("LORE_G8_ACCESS_TOKEN")?,
                identity: std::env::var("LORE_G8_IDENTITY_TOKEN").unwrap_or_default(),
            })
        }

        async fn session(
            &self,
            url: &str,
        ) -> Result<Arc<lore_transport::session::StorageSession>, ProtocolError> {
            session(url, self.partition, &self.identity, &self.access).await
        }
    }

    fn managed_scope(partition: RepositoryId) -> CallerOperationContext {
        CallerOperationContext::new(
            uuid::Uuid::now_v7(),
            partition,
            Arc::new(ManagedJournal::default()),
        )
    }

    /// Records each leg as it is printed, so the test can prove every expected leg ran.
    #[derive(Default)]
    struct Legs {
        recorded: Vec<&'static str>,
        failures: Vec<&'static str>,
    }

    impl Legs {
        fn record(&mut self, name: &'static str, pass: bool, detail: &str) {
            println!(
                "G8-LEG {}",
                serde_json::json!({ "leg": name, "result": if pass { "pass" } else { "fail" }, "detail": detail })
            );
            self.recorded.push(name);
            if !pass {
                self.failures.push(name);
            }
        }

        /// Fails when a leg failed, or when the recorded legs are not exactly the expected ones.
        fn verdict(self) -> TestResult {
            if self.recorded != EXPECTED_LEGS {
                return Err(format!(
                    "recorded legs {:?} are not the expected {:?}; a leg that did not run is not a pass",
                    self.recorded, EXPECTED_LEGS
                )
                .into());
            }
            if self.failures.is_empty() {
                Ok(())
            } else {
                Err(format!("legs failed: {}", self.failures.join(", ")).into())
            }
        }
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
    async fn live_strict_cell_admits_only_declared_quic_writes() -> TestResult {
        let cell = LiveCell::from_env()?;
        let execution = setup_execution("g8-live-probe".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let mut legs = Legs::default();

                // 1. A managed gRPC Put is admitted.
                let grpc = cell.session(&cell.grpc_url).await?;
                let (seeded, seeded_address, seeded_payload) = fragment::generate_random();
                let managed = with_caller_operation(
                    managed_scope(cell.partition),
                    grpc.put(seeded_address, seeded, Some(seeded_payload.clone())),
                )
                .await;
                legs.record(
                    "managed-grpc-write",
                    managed.is_ok(),
                    &format!("{managed:?} address={seeded_address}"),
                );

                // 2. A stock QUIC Get of that fragment returns its bytes.
                let quic = cell.session(&cell.quic_url).await?;
                let read = quic.get(&seeded_address).await;
                let read_ok = matches!(&read, Ok((_, payload)) if *payload == seeded_payload);
                legs.record(
                    "quic-read-undeclared",
                    read_ok,
                    &match &read {
                        Ok((_, payload)) => format!("Ok({} bytes)", payload.len()),
                        Err(error) => format!("Err({error:?})"),
                    },
                );

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
                legs.record(
                    "quic-write-undeclared",
                    refused_200,
                    &format!("{detail} address={refused_address}"),
                );

                // 4. The refused fragment is absent: a read of it answers NotFound. Any other
                // error (auth, transport, server failure) proves nothing about absence.
                let absent = quic.get(&refused_address).await;
                let not_found = matches!(&absent, Err(ProtocolError::NotFound(_)));
                legs.record(
                    "quic-write-absent",
                    not_found,
                    &match &absent {
                        Ok((_, payload)) => format!("Ok({} bytes) PRESENT", payload.len()),
                        Err(error) => format!("Err({error:?})"),
                    },
                );

                // 5. A managed Put over QUIC is admitted. The scope's declared-session count is
                // the transport's own record that the Put went out on a declared QUIC session;
                // it is 0 for a gRPC write, so a write that quietly fell back to gRPC fails here.
                let (written, written_address, written_payload) = fragment::generate_random();
                let scope = managed_scope(cell.partition);
                let quic_scheme = cell.quic_url.split("://").next().unwrap_or_default();
                let managed_quic = with_caller_operation(
                    scope.clone(),
                    quic.put(written_address, written, Some(written_payload.clone())),
                )
                .await;
                let declared = scope.declared_session_count();
                let is_quic_url = matches!(quic_scheme, "lore" | "lores");
                legs.record(
                    "managed-quic-write",
                    managed_quic.is_ok() && declared == 1 && is_quic_url,
                    &format!(
                        "{managed_quic:?} declared_sessions={declared} scheme={quic_scheme} \
                         address={written_address}"
                    ),
                );

                // 6. The managed write reads back over QUIC, on a fresh connection so the bytes
                // come from the cell's store and not from anything the writing session holds.
                let reader = cell.session(&cell.quic_url).await?;
                let back = reader.get(&written_address).await;
                let back_ok = matches!(&back, Ok((_, payload)) if *payload == written_payload);
                legs.record(
                    "managed-quic-read-back",
                    back_ok,
                    &match &back {
                        Ok((_, payload)) => {
                            format!("Ok({} bytes) matches={back_ok}", payload.len())
                        }
                        Err(error) => format!("Err({error:?})"),
                    },
                );

                legs.verdict()
            })
            .await
    }

    /// Calls per series. Small and fixed: this is a cost probe against a live cell, not a load test.
    const COST_CALLS: usize = 20;

    /// Millisecond summary of one series, printed as one `G8-COST` line.
    struct Series {
        name: &'static str,
        /// Wall time of each call in milliseconds, in call order.
        samples_ms: Vec<f64>,
    }

    impl Series {
        fn sorted(&self) -> Vec<f64> {
            let mut sorted = self.samples_ms.clone();
            sorted.sort_by(f64::total_cmp);
            sorted
        }

        /// Nearest-rank percentile: the smallest sample with at least `p` of the samples at or
        /// below it.
        fn percentile(&self, p: f64) -> f64 {
            let sorted = self.sorted();
            if sorted.is_empty() {
                return f64::NAN;
            }
            let rank = (p * sorted.len() as f64).ceil().max(1.0) as usize;
            sorted[rank.min(sorted.len()) - 1]
        }

        fn mean(&self) -> f64 {
            if self.samples_ms.is_empty() {
                return f64::NAN;
            }
            self.samples_ms.iter().sum::<f64>() / self.samples_ms.len() as f64
        }

        fn print(&self, extra: serde_json::Value) {
            let mut line = serde_json::json!({
                "series": self.name,
                "count": self.samples_ms.len(),
                "p50_ms": self.percentile(0.50),
                "p95_ms": self.percentile(0.95),
                "mean_ms": self.mean(),
            });
            if let (Some(line), Some(extra)) = (line.as_object_mut(), extra.as_object()) {
                line.extend(extra.clone());
            }
            println!("G8-COST {line}");
        }
    }

    fn milliseconds(elapsed: Duration) -> f64 {
        elapsed.as_secs_f64() * 1000.0
    }

    /// What a declared session costs one caller, against the live replica in the same environment
    /// as the legs test. Three series of `COST_CALLS` calls, one `G8-COST {json}` line each:
    ///
    ///   undeclared-quic-read       baseline: a stock QUIC Get of one fragment (undeclared writes
    ///                              are refused, so reads are the only undeclared traffic)
    ///   declared-write-new-scope   a NEW `CallerOperationContext` per call and one small managed
    ///                              QUIC Put inside it. Each call pays a declared `AuthorizeStart`
    ///                              round trip plus the Put. Timed from before the scope is made to
    ///                              after the Put returns.
    ///   declared-write-one-scope   the same small Put, `COST_CALLS` times inside ONE scope that
    ///                              already holds its declared session (one unmeasured warm-up Put
    ///                              starts it). No call pays a start.
    ///
    /// The declared-start cost per call is derived as the new-scope series minus the one-scope
    /// series (mean and p50), printed on the new-scope line as `derived_start_cost_*_ms`. It is a
    /// difference of two live-network series: noise can make it negative or tiny, and the line
    /// reports it as measured.
    ///
    /// The stop is not in the numbers and cannot be witnessed from outside the cell. A declared
    /// session's stop is sent from a spawned task when the scope's last clone drops (see
    /// `SessionBinding::drop` in `lore-transport/src/session.rs`) and its result is discarded, so
    /// the caller never waits on it. The server's session count is not visible from a client. What
    /// this test can show is the client side: each new-scope call recorded exactly one declared
    /// session (`declared_session_count() == 1` before the scope drops), which is the session whose
    /// stop is then sent. The new-scope line also carries `loop_wall_ms`, the whole loop including
    /// every scope drop, so a stop that blocked the caller would show there.
    ///
    /// Pass condition: every call in every series succeeded, and each new-scope call and the
    /// one-scope series recorded the declared-session count they should.
    #[tokio::test]
    #[ignore = "needs a live strict QUIC-on cell; driven by lorehub's dev-cell-admission-probe"]
    async fn live_declared_session_cost() -> TestResult {
        let cell = LiveCell::from_env()?;
        let execution = setup_execution("g8-live-cost".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let quic = cell.session(&cell.quic_url).await?;

                // Seed one fragment for the read baseline (managed, so a strict cell admits it).
                let (seed, seed_address, seed_payload) = fragment::generate_random();
                with_caller_operation(
                    managed_scope(cell.partition),
                    quic.put(seed_address, seed, Some(seed_payload)),
                )
                .await?;

                let mut failures: Vec<String> = Vec::new();
                // Calls that fully succeeded, counted per call (one call can add two failures).
                let mut read_ok = 0_usize;
                let mut new_scope_ok = 0_usize;
                let mut one_scope_ok = 0_usize;

                // Baseline: undeclared reads. One unmeasured warm-up read first.
                quic.get(&seed_address).await?;
                let mut reads = Series {
                    name: "undeclared-quic-read",
                    samples_ms: Vec::new(),
                };
                for call in 0..COST_CALLS {
                    let start = Instant::now();
                    let read = quic.get(&seed_address).await;
                    reads.samples_ms.push(milliseconds(start.elapsed()));
                    match read {
                        Ok(_) => read_ok += 1,
                        Err(error) => failures.push(format!("undeclared read {call}: {error:?}")),
                    }
                }
                reads.print(serde_json::json!({ "successes": read_ok }));

                // A NEW scope per call. The first Put in a scope pays the declared start.
                let mut new_scope = Series {
                    name: "declared-write-new-scope",
                    samples_ms: Vec::new(),
                };
                let loop_start = Instant::now();
                for call in 0..COST_CALLS {
                    let (fragment, address, payload) = fragment::generate_random();
                    let start = Instant::now();
                    let scope = managed_scope(cell.partition);
                    let put = with_caller_operation(
                        scope.clone(),
                        quic.put(address, fragment, Some(payload)),
                    )
                    .await;
                    new_scope.samples_ms.push(milliseconds(start.elapsed()));
                    let mut call_ok = true;
                    if let Err(error) = put {
                        failures.push(format!("new-scope write {call}: {error:?}"));
                        call_ok = false;
                    }
                    if scope.declared_session_count() != 1 {
                        failures.push(format!(
                            "new-scope write {call}: declared_session_count={} (expected 1)",
                            scope.declared_session_count()
                        ));
                        call_ok = false;
                    }
                    new_scope_ok += usize::from(call_ok);
                    // `scope` drops here: its last clone is gone and the stop is sent.
                }
                let loop_wall_ms = milliseconds(loop_start.elapsed());

                // ONE scope, already declared by an unmeasured warm-up Put.
                let scope = managed_scope(cell.partition);
                let (fragment, address, payload) = fragment::generate_random();
                with_caller_operation(scope.clone(), quic.put(address, fragment, Some(payload)))
                    .await?;
                let mut one_scope = Series {
                    name: "declared-write-one-scope",
                    samples_ms: Vec::new(),
                };
                for call in 0..COST_CALLS {
                    let (fragment, address, payload) = fragment::generate_random();
                    let start = Instant::now();
                    let put = with_caller_operation(
                        scope.clone(),
                        quic.put(address, fragment, Some(payload)),
                    )
                    .await;
                    one_scope.samples_ms.push(milliseconds(start.elapsed()));
                    match put {
                        Ok(()) => one_scope_ok += 1,
                        Err(error) => failures.push(format!("one-scope write {call}: {error:?}")),
                    }
                }
                if scope.declared_session_count() != 1 {
                    failures.push(format!(
                        "one-scope series: declared_session_count={} (expected 1)",
                        scope.declared_session_count()
                    ));
                }

                new_scope.print(serde_json::json!({
                    "successes": new_scope_ok,
                    "loop_wall_ms": loop_wall_ms,
                    "derived_start_cost_mean_ms": new_scope.mean() - one_scope.mean(),
                    "derived_start_cost_p50_ms":
                        new_scope.percentile(0.50) - one_scope.percentile(0.50),
                    "derived_from": "declared-write-new-scope minus declared-write-one-scope",
                }));
                one_scope.print(serde_json::json!({
                    "successes": one_scope_ok,
                }));

                if failures.is_empty() {
                    Ok(())
                } else {
                    Err(format!("calls failed: {}", failures.join("; ")).into())
                }
            })
            .await
    }
}

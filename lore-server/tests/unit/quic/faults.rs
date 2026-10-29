// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Tests for `lore_server::quic::faults` (WP-124 follow-up (d)): the QUIC storage fault seam.
//!
//! [SERVER] test-only module. Every behavioural test builds its own `Registry`, never the global
//! `registry()`, so the tests stay isolated from each other and from the storage hooks.
//!
//! Only `dockerfile_never_builds_the_failure_generator_feature` runs in a default build. It is the
//! guard for the module's one real risk: shipping the fault listener in an image.

/// The staging cell build (`lorehub/deploy/staging/deploy-cell.ps1`, the `docker build` of
/// `lore-server/Dockerfile`) uses this file unchanged. A `failure_generator` mention in it would put
/// the QUIC fault-control listener (withhold a write's answer, close a connection, expire a
/// session) into the image a cell serves production traffic from. The Dockerfile must never name
/// the feature, nor `--all-features`, which enables it without naming it, so a test image has to
/// be built by a separate, explicit command.
#[test]
fn dockerfile_never_builds_the_failure_generator_feature() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Dockerfile");
    let dockerfile = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    for forbidden in ["failure_generator", "--all-features"] {
        assert!(
            !dockerfile.contains(forbidden),
            "{} mentions `{forbidden}`: the staging build uses this file unchanged, so the QUIC \
             fault-control listener would ship in the production cell image",
            path.display()
        );
    }
}

#[cfg(feature = "failure_generator")]
mod compiled {
    use std::time::Duration;

    use axum_test::TestServer;
    use lore_base::types::Address;
    use lore_base::types::Hash;
    use lore_revision::lore::RepositoryId;
    use lore_server::quic::faults::ArmError;
    use lore_server::quic::faults::ArmRequest;
    use lore_server::quic::faults::Fault;
    use lore_server::quic::faults::HoldEnd;
    use lore_server::quic::faults::Registry;
    use lore_server::quic::faults::WriteVerb;
    use lore_server::quic::faults::control_router;
    use lore_server::quic::faults::reserved_ports;
    use lore_server::quic::faults::validate_control_address;
    use lore_server::settings::Settings;
    use serde_json::Value;
    use serde_json::json;

    const REPO_HEX: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_HEX: &str = "fedcba9876543210fedcba9876543210";

    fn repo(hex: &str) -> RepositoryId {
        hex.parse().expect("test repository hex parses")
    }

    fn request(fault: Fault, repository: &str, verb: Option<WriteVerb>) -> ArmRequest {
        ArmRequest {
            fault,
            repository: repository.to_string(),
            verb,
        }
    }

    fn arm(registry: &Registry, fault: Fault, verb: Option<WriteVerb>) {
        registry
            .arm(request(fault, REPO_HEX, verb))
            .expect("the first arm succeeds");
    }

    // ---- Registry: arm ----

    #[test]
    fn arm_refuses_a_malformed_repository() {
        let registry = Registry::default();
        for bad in [
            "zz23456789abcdef0123456789abcdef",   // not hex
            "0123456789abcdef",                   // too short
            "0123456789abcdef0123456789abcdef00", // too long
            "0123456789ABCDEF0123456789ABCDEF",   // uppercase
            "",
        ] {
            assert_eq!(
                registry.arm(request(Fault::AnswerLoss, bad, None)).err(),
                Some(ArmError::InvalidRepository),
                "{bad:?} must be refused"
            );
        }
        assert!(
            registry.state().armed.is_none(),
            "a refused arm leaves nothing armed"
        );
    }

    #[test]
    fn a_second_arm_is_refused_while_one_is_armed() {
        let registry = Registry::default();
        arm(&registry, Fault::AnswerLoss, None);
        assert_eq!(
            registry
                .arm(request(Fault::ExpireSession, OTHER_HEX, None))
                .err(),
            Some(ArmError::AlreadyArmed)
        );
        let armed = registry.state().armed.expect("the first arm stays");
        assert_eq!(armed.fault, Fault::AnswerLoss);
        assert_eq!(armed.repository, REPO_HEX);
    }

    #[test]
    fn verb_defaults_to_put() {
        let registry = Registry::default();
        let armed = registry
            .arm(request(Fault::ExpireSession, REPO_HEX, None))
            .expect("arm");
        assert_eq!(armed.verb, WriteVerb::Put);
        assert_eq!(registry.state().armed.expect("armed").verb, WriteVerb::Put);
    }

    #[test]
    fn disarm_clears_an_unfired_arm_and_allows_a_new_one() {
        let registry = Registry::default();
        arm(&registry, Fault::ExpireSession, None);
        registry.disarm();
        assert!(registry.state().armed.is_none());
        assert!(!registry.force_expired(None, 1, repo(REPO_HEX), true, Some(WriteVerb::Put)));
        // The arm id advances: a re-arm is a new arm.
        let again = registry
            .arm(request(Fault::ExpireSession, REPO_HEX, None))
            .expect("re-arm after disarm");
        assert_eq!(again.id, 2);
    }

    // ---- force_expired ----

    #[test]
    fn force_expired_fires_once_and_records_a_never_dispatched_command() {
        let registry = Registry::default();
        arm(&registry, Fault::ExpireSession, Some(WriteVerb::Put));
        let repository = repo(REPO_HEX);

        assert!(registry.force_expired(Some(7), 42, repository, true, Some(WriteVerb::Put)));
        assert!(
            !registry.force_expired(Some(7), 42, repository, true, Some(WriteVerb::Put)),
            "the arm is spent by the first claim"
        );

        let state = registry.state();
        assert!(state.armed.is_none());
        assert_eq!(state.fired.len(), 1);
        let firing = &state.fired[0];
        assert_eq!(firing.fault, Fault::ExpireSession);
        assert_eq!(firing.verb, WriteVerb::Put);
        assert_eq!(firing.repository, REPO_HEX);
        assert_eq!(firing.connection_id, Some(7));
        assert_eq!(firing.session_id, 42);
        assert!(
            !firing.store_accepted,
            "an expired command is never dispatched"
        );
        assert_eq!(firing.address, None);
        assert!(!firing.connection_closed);
        assert_eq!(firing.hold_end, None, "only answer-loss holds");
    }

    #[test]
    fn force_expired_with_no_write_verb_neither_fires_nor_spends_the_arm() {
        let registry = Registry::default();
        arm(&registry, Fault::ExpireSession, None);
        assert!(!registry.force_expired(None, 1, repo(REPO_HEX), true, None));
        assert!(registry.state().armed.is_some());
        assert!(registry.state().fired.is_empty());
    }

    #[test]
    fn a_non_matching_command_neither_fires_nor_spends_the_arm() {
        let registry = Registry::default();
        arm(&registry, Fault::ExpireSession, Some(WriteVerb::Put));
        // Other repository, other verb, undeclared session.
        assert!(!registry.force_expired(None, 1, repo(OTHER_HEX), true, Some(WriteVerb::Put)));
        assert!(!registry.force_expired(None, 1, repo(REPO_HEX), true, Some(WriteVerb::Copy)));
        assert!(!registry.force_expired(None, 1, repo(REPO_HEX), false, Some(WriteVerb::Put)));
        let state = registry.state();
        assert!(
            state.armed.is_some(),
            "the arm stays for the matching command"
        );
        assert!(state.fired.is_empty());
        // The matching command still claims it.
        assert!(registry.force_expired(None, 1, repo(REPO_HEX), true, Some(WriteVerb::Put)));
    }

    #[test]
    fn expire_session_does_not_fire_from_the_after_write_hook() {
        // `after_write` only claims the answer faults; an expiry is a pre-dispatch fault.
        let registry = Registry::default();
        arm(&registry, Fault::ExpireSession, None);
        let outcome = futures_ready(registry.after_write(
            None,
            None,
            1,
            repo(REPO_HEX),
            true,
            WriteVerb::Put,
            None,
        ));
        assert!(
            outcome,
            "after_write returns at once for a non-answer fault"
        );
        assert!(registry.state().armed.is_some());
        assert!(registry.state().fired.is_empty());
    }

    /// Whether `future` completes at once (one poll with a no-op waker).
    fn futures_ready(future: impl std::future::Future<Output = ()>) -> bool {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        future.as_mut().poll(&mut context).is_ready()
    }

    // ---- after_write ----

    #[tokio::test(start_paused = true)]
    async fn answer_loss_holds_the_answer_until_disarm() {
        let registry = Registry::default();
        arm(&registry, Fault::AnswerLoss, Some(WriteVerb::Put));
        let address = Address::zero_context_hash(Hash::from_u64(9));

        let held = registry.after_write(
            Some(3),
            None,
            11,
            repo(REPO_HEX),
            true,
            WriteVerb::Put,
            Some(&address),
        );
        let mut held = std::pin::pin!(held);

        // Long past any plausible latency, on a paused clock: still held.
        assert!(
            tokio::time::timeout(Duration::from_secs(3600), held.as_mut())
                .await
                .is_err(),
            "the answer must stay held until a disarm"
        );
        let state = registry.state();
        assert_eq!(state.held, 1, "one answer is held");
        assert!(state.armed.is_none(), "the claim spent the arm");
        let firing = &state.fired[0];
        assert_eq!(firing.fault, Fault::AnswerLoss);
        assert!(firing.store_accepted);
        assert_eq!(
            firing.address.as_deref(),
            Some(address.to_string().as_str())
        );
        assert_eq!(firing.connection_id, Some(3));
        assert_eq!(firing.session_id, 11);
        assert_eq!(firing.hold_end, None, "still held");

        registry.disarm();
        tokio::time::timeout(Duration::from_secs(5), held.as_mut())
            .await
            .expect("a disarm releases the held answer");
        let state = registry.state();
        assert_eq!(state.held, 0, "nothing is held after the release");
        assert_eq!(
            state.fired[0].hold_end,
            Some(HoldEnd::Disarm),
            "the released hold records the disarm"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_hold_is_counted_down_and_recorded_cancelled() {
        let registry = Registry::default();
        arm(&registry, Fault::AnswerLoss, None);
        {
            let held =
                registry.after_write(None, None, 1, repo(REPO_HEX), true, WriteVerb::Put, None);
            let mut held = std::pin::pin!(held);
            assert!(
                tokio::time::timeout(Duration::from_secs(60), held.as_mut())
                    .await
                    .is_err()
            );
            assert_eq!(registry.state().held, 1);
        }
        // The command's task was dropped mid-hold (a stream reset, a shutdown).
        let state = registry.state();
        assert_eq!(state.held, 0, "a cancelled hold must not stay counted");
        assert_eq!(state.fired[0].hold_end, Some(HoldEnd::Cancelled));
        // A later disarm does not rewrite how that hold ended.
        registry.disarm();
        assert_eq!(registry.state().fired[0].hold_end, Some(HoldEnd::Cancelled));
    }

    #[tokio::test]
    async fn disarm_does_not_mark_a_non_holding_firing() {
        let registry = Registry::default();
        arm(&registry, Fault::CloseAfterAnswer, None);
        tokio::time::timeout(
            Duration::from_secs(5),
            registry.after_write(None, None, 1, repo(REPO_HEX), true, WriteVerb::Put, None),
        )
        .await
        .expect("close-after-answer never holds");
        registry.disarm();
        assert_eq!(registry.state().fired[0].hold_end, None);
    }

    #[tokio::test(start_paused = true)]
    async fn answer_loss_is_one_shot() {
        let registry = Registry::default();
        arm(&registry, Fault::AnswerLoss, None);
        let first = registry.after_write(None, None, 1, repo(REPO_HEX), true, WriteVerb::Put, None);
        let mut first = std::pin::pin!(first);
        assert!(
            tokio::time::timeout(Duration::from_secs(60), first.as_mut())
                .await
                .is_err()
        );
        // An identical second command is answered at once. Bounded, so a broken one-shot fails
        // here instead of hanging the binary.
        tokio::time::timeout(
            Duration::from_secs(5),
            registry.after_write(None, None, 1, repo(REPO_HEX), true, WriteVerb::Put, None),
        )
        .await
        .expect("a spent arm must not hold a second command");
        assert_eq!(registry.state().fired.len(), 1);
        registry.disarm();
        tokio::time::timeout(Duration::from_secs(5), first)
            .await
            .expect("a disarm releases the first hold");
    }

    #[tokio::test]
    async fn answer_faults_ignore_a_non_matching_write() {
        let registry = Registry::default();
        arm(&registry, Fault::AnswerLoss, Some(WriteVerb::Put));
        let address = Address::zero_context_hash(Hash::from_u64(1));
        for (repository, declared, verb) in [
            (repo(OTHER_HEX), true, WriteVerb::Put),
            (repo(REPO_HEX), true, WriteVerb::Copy),
            (repo(REPO_HEX), false, WriteVerb::Put),
        ] {
            tokio::time::timeout(
                Duration::from_secs(5),
                registry.after_write(None, None, 1, repository, declared, verb, Some(&address)),
            )
            .await
            .expect("a non-matching write is never held");
        }
        let state = registry.state();
        assert!(
            state.armed.is_some(),
            "the arm survives non-matching writes"
        );
        assert!(state.fired.is_empty());
        assert_eq!(state.held, 0);
    }

    #[tokio::test]
    async fn close_after_answer_without_a_connection_returns_at_once() {
        let registry = Registry::default();
        arm(
            &registry,
            Fault::CloseAfterAnswer,
            Some(WriteVerb::PutResolved),
        );
        // Completes with no timeout and no disarm: there is nothing to hold.
        tokio::time::timeout(
            Duration::from_secs(5),
            registry.after_write(
                None,
                None,
                1,
                repo(REPO_HEX),
                true,
                WriteVerb::PutResolved,
                None,
            ),
        )
        .await
        .expect("close-after-answer never holds the answer");
        let state = registry.state();
        assert_eq!(state.held, 0);
        let firing = &state.fired[0];
        assert_eq!(firing.fault, Fault::CloseAfterAnswer);
        assert_eq!(firing.verb, WriteVerb::PutResolved);
        assert!(firing.store_accepted);
        assert!(
            !firing.connection_closed,
            "no connection handle was present"
        );
    }

    // ---- validate_control_address / reserved_ports ----

    #[test]
    fn control_address_accepts_loopback_only() {
        assert_eq!(
            validate_control_address("127.0.0.1:41999", &[41337])
                .expect("v4 loopback")
                .to_string(),
            "127.0.0.1:41999"
        );
        assert_eq!(
            validate_control_address("[::1]:41999", &[41337])
                .expect("v6 loopback")
                .to_string(),
            "[::1]:41999"
        );
    }

    #[test]
    fn control_address_refuses_unsafe_values() {
        let reserved = [41337, 41340];
        for (raw, why) in [
            ("0.0.0.0:41999", "unspecified is not loopback"),
            ("192.168.1.10:41999", "a LAN address"),
            ("[::]:41999", "v6 unspecified"),
            ("127.0.0.1:0", "port 0"),
            ("127.0.0.1:41337", "a reserved listener port"),
            ("[::1]:41340", "a reserved listener port on v6"),
            ("localhost:41999", "not a socket address"),
            ("127.0.0.1", "no port"),
            ("", "empty"),
        ] {
            assert!(
                validate_control_address(raw, &reserved).is_err(),
                "{raw:?} must be refused ({why})"
            );
        }
    }

    #[test]
    fn reserved_ports_lists_every_configured_listener() {
        let settings: Settings = toml::from_str(include_str!("../../../config/default.toml"))
            .expect("built-in settings fixture must deserialize");
        let mut ports = reserved_ports(&settings);
        ports.sort_unstable();
        ports.dedup();
        // default.toml: quic/grpc 41337, http 41339, quic_internal/grpc_internal 41340.
        assert_eq!(ports, vec![41337, 41339, 41340]);
        for port in [41337u16, 41339, 41340] {
            assert!(
                validate_control_address(&format!("127.0.0.1:{port}"), &reserved_ports(&settings))
                    .is_err(),
                "the control listener must never share port {port}"
            );
        }
    }

    // ---- control_router ----

    fn server(registry: &std::sync::Arc<Registry>) -> TestServer {
        TestServer::new(control_router(registry.clone())).expect("test server")
    }

    #[tokio::test]
    async fn router_reports_state() {
        let registry = std::sync::Arc::new(Registry::default());
        let response = server(&registry).get("/quic-faults/state").await;
        response.assert_status_ok();
        let body: Value = response.json();
        assert_eq!(body["compiled"], json!(true));
        assert_eq!(body["armed"], Value::Null);
        assert_eq!(body["held"], json!(0));
        assert_eq!(body["fired"], json!([]));
    }

    #[tokio::test]
    async fn router_arm_is_200_then_409() {
        let registry = std::sync::Arc::new(Registry::default());
        let server = server(&registry);
        let body = json!({"fault": "answer-loss", "repository": REPO_HEX, "verb": "copy"});

        let first = server.post("/quic-faults/arm").json(&body).await;
        first.assert_status_ok();
        let state: Value = first.json();
        assert_eq!(state["armed"]["fault"], json!("answer-loss"));
        assert_eq!(state["armed"]["verb"], json!("copy"));
        assert_eq!(state["armed"]["repository"], json!(REPO_HEX));
        assert!(registry.state().armed.is_some());

        let second = server.post("/quic-faults/arm").json(&body).await;
        second.assert_status(axum::http::StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn router_arm_defaults_the_verb_to_put() {
        let registry = std::sync::Arc::new(Registry::default());
        let response = server(&registry)
            .post("/quic-faults/arm")
            .json(&json!({"fault": "expire-session", "repository": REPO_HEX}))
            .await;
        response.assert_status_ok();
        let state: Value = response.json();
        assert_eq!(state["armed"]["verb"], json!("put"));
    }

    #[tokio::test]
    async fn router_refuses_a_bad_repository_with_400() {
        let registry = std::sync::Arc::new(Registry::default());
        let response = server(&registry)
            .post("/quic-faults/arm")
            .json(&json!({"fault": "answer-loss", "repository": "NOT-A-REPOSITORY"}))
            .await;
        response.assert_status(axum::http::StatusCode::BAD_REQUEST);
        assert!(registry.state().armed.is_none());
    }

    #[tokio::test]
    async fn router_rejects_an_unknown_json_field() {
        let registry = std::sync::Arc::new(Registry::default());
        let response = server(&registry)
            .post("/quic-faults/arm")
            .json(&json!({
                "fault": "answer-loss",
                "repository": REPO_HEX,
                "extra": true,
            }))
            .await;
        response.assert_status(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            registry.state().armed.is_none(),
            "a rejected body must not arm anything"
        );
    }

    #[tokio::test]
    async fn router_disarm_clears_the_arm() {
        let registry = std::sync::Arc::new(Registry::default());
        let server = server(&registry);
        server
            .post("/quic-faults/arm")
            .json(&json!({"fault": "close-after-answer", "repository": REPO_HEX}))
            .await
            .assert_status_ok();
        let response = server.post("/quic-faults/disarm").await;
        response.assert_status_ok();
        let state: Value = response.json();
        assert_eq!(state["armed"], Value::Null);
        assert!(registry.state().armed.is_none());
    }
}

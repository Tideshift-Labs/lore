// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Structural pins for the coordinated immutable-store PUT route.
//!
//! The legacy route intentionally retains its historical raw S3 transaction.
//! These assertions therefore isolate the coordinated early return and its
//! helpers rather than claiming the whole source file is SDK-free.

use std::path::PathBuf;

fn source(relative: &str) -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"))
}

fn function<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing function marker {marker:?}"));
    let tail = &source[start..];
    let opening = tail.find('{').expect("function opening brace");
    let mut depth = 0usize;
    for (offset, byte) in tail.as_bytes()[opening..].iter().copied().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &tail[..opening + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function {marker:?}")
}

fn assert_verification_uncertainty_fails_closed(verify: &str) {
    assert!(verify.contains(
        "(ProviderAttemptOutcome::Decisive, FragmentGetResponse::Throttled)\n            | (ProviderAttemptOutcome::Ambiguous, _) => Err(StoreError::from(SlowDown))"
    ));
    assert!(
        !verify.contains(".commit_remote(") && !verify.contains(".mark_missing("),
        "verification cannot publish a lifecycle verdict itself"
    );
}

fn assert_resolved_client_attestation(constructor: &str) {
    assert!(constructor.contains("client\n            .config()\n            .region()"));
    assert!(constructor.contains("normalize_region(value.as_ref())"));
    assert!(constructor.contains("let target_region = normalize_region(&region)"));
    assert!(constructor.contains("if resolved_region != target_region"));
    assert!(constructor.contains("normalize_endpoint_host(resolved_endpoint_url)"));
    assert!(constructor.contains("let target_endpoint_host = normalize_dns_name(&endpoint_host)"));
    assert!(constructor.contains("if resolved_endpoint_host != target_endpoint_host"));
    assert!(constructor.contains("region: target_region"));
    assert!(constructor.contains("endpoint_host: target_endpoint_host"));
}

#[test]
fn coordinated_put_returns_before_the_legacy_connection_transaction_and_raw_sdk_branch() {
    let immutable = source("src/store/immutable_store.rs");
    let put = function(&immutable, "async fn put(\n");
    let route = put
        .find("FragmentLifecycleRoute::Coordinated")
        .expect("coordinated route branch");
    let delegated = put[route..]
        .find("return self")
        .map(|offset| route + offset)
        .expect("coordinated route must return its delegated future");
    let legacy_checkout = put
        .find("self.pool.get()")
        .expect("legacy route remains explicitly present");
    let legacy_put = put
        .find("self.s3\n            .put_object")
        .expect("legacy raw PUT remains explicitly present");

    assert!(put[delegated..legacy_checkout].contains(".put_coordinated("));
    assert!(route < delegated && delegated < legacy_checkout && legacy_checkout < legacy_put);
}

#[test]
fn coordinated_put_and_direct_provider_io_hold_no_store_connection_transaction_or_lock() {
    let immutable = source("src/store/immutable_store.rs");
    for (name, body) in [
        (
            "put_coordinated",
            function(&immutable, "async fn put_coordinated("),
        ),
        (
            "issue_direct_put",
            function(&immutable, "async fn issue_direct_put("),
        ),
    ] {
        for forbidden in [
            "self.pool.get()",
            ".transaction()",
            "lock_hash",
            "self.s3",
            ".put_object(",
        ] {
            assert!(
                !body.contains(forbidden),
                "{name} names {forbidden:?}; provider I/O must not span a store DB resource"
            );
        }
    }
}

#[test]
fn ordinary_direct_write_supplies_the_legacy_hash_key_but_missing_uses_a_repair_epoch_key() {
    let immutable = source("src/store/immutable_store.rs");
    let coordinated = function(&immutable, "async fn put_coordinated(");
    assert!(coordinated.contains("let legacy_key = Self::hash_key(address.hash);"));
    assert!(
        coordinated.contains(".begin_direct_write(address.hash.data(), &legacy_key, write_claim)")
    );
    assert!(
        function(&immutable, "async fn issue_direct_put(")
            .contains("object_key: request.intent.object_key.clone()")
    );

    let coordinator = source("src/domain/fragments/coordinator.rs");
    let publication = function(&coordinator, "async fn begin_publication(");
    assert!(publication.contains("(repair_epoch_key(hash, epoch), Some(DirectWriteKind::Repair))"));
    assert!(publication.contains("(key.to_owned(), Some(DirectWriteKind::Normal))"));
}

#[test]
fn persisted_direct_write_lineage_drives_retry_traffic_class_and_uncertainty_commits_nothing() {
    let immutable = source("src/store/immutable_store.rs");
    let issue = function(&immutable, "async fn issue_direct_put(");
    assert!(
        issue.contains("Some(DirectWriteKind::Normal) => ProviderTrafficClass::DirectFallback")
    );
    assert!(issue.contains("Some(DirectWriteKind::Repair) => ProviderTrafficClass::Repair"));
    assert!(issue.contains("None =>"));

    let coordinated = function(&immutable, "async fn put_coordinated(");
    let begin = coordinated
        .find(".begin_direct_write(address.hash.data(), &legacy_key, write_claim)")
        .expect("durable begin/resume");
    let provider = coordinated
        .find("CoordinatedDirectPut {")
        .expect("provider I/O uses returned intent");
    let uncertainty = coordinated[provider..]
        .find(".await?;")
        .map(|offset| provider + offset)
        .expect("provider uncertainty returns before commit");
    let commit = coordinated
        .find(".commit_remote(&intent, observation, settlement)")
        .expect("commit the observation and exact claim settlement");
    assert!(begin < provider && provider < uncertainty && uncertainty < commit);
}

#[test]
fn coordinated_put_without_payload_is_db_only_and_requires_an_exact_readable_association() {
    let immutable = source("src/store/immutable_store.rs");
    let coordinated = function(&immutable, "async fn put_coordinated(");
    let none = coordinated
        .find("let Some(payload) = payload else")
        .expect("None branch");
    let preflight = coordinated
        .find("let preflight_manifest")
        .expect("payload path");
    let none_branch = &coordinated[none..preflight];

    assert!(none_branch.contains("Self::resolve_one(coordinator, repository, address)"));
    assert!(none_branch.contains("FragmentVerdict::Readable { .. } => Ok(())"));
    assert!(none_branch.contains("FragmentVerdict::Absent => Err(StoreError::internal("));
    assert!(none_branch.contains("fragment direct PUT requires payload bytes"));
    for forbidden in [
        "begin_direct_write",
        "admit_put",
        "issue_direct_put",
        "commit_remote",
    ] {
        assert!(
            !none_branch.contains(forbidden),
            "payload-free branch must perform no provider lifecycle operation {forbidden:?}"
        );
    }
}

#[test]
fn coordinated_remote_get_only_a_decisive_not_found_can_mark_missing() {
    let immutable = source("src/store/immutable_store.rs");
    let load = function(&immutable, "async fn load_coordinated(");
    let compact = load.split_whitespace().collect::<Vec<_>>().join(" ");
    let tuple_match = compact
        .find("match (execution.outcome, execution.response)")
        .expect("remote GET must classify the governed outcome and response together");
    let found = compact[tuple_match..]
        .find("ProviderAttemptOutcome::Decisive, FragmentGetResponse::Found")
        .map(|offset| tuple_match + offset)
        .expect("only a decisive Found response enters validation");
    let not_found = compact[found..]
        .find("(ProviderAttemptOutcome::Decisive, FragmentGetResponse::NotFound)")
        .map(|offset| found + offset)
        .expect("only a decisive NotFound response may mark Missing");
    let throttled = compact[not_found..]
        .find("(ProviderAttemptOutcome::Decisive, FragmentGetResponse::Throttled)")
        .map(|offset| not_found + offset)
        .expect("decisive throttling remains transient");
    let staged = compact[throttled..]
        .find("EpochAuthority::Staged")
        .map(|offset| throttled + offset)
        .expect("staged-read branch follows remote classification");

    assert!(
        tuple_match < found && found < not_found && not_found < throttled && throttled < staged
    );
    assert!(compact[found..not_found].contains("Self::validate_candidate("));
    assert!(compact[not_found..throttled].contains("Self::mark_coordinated_missing("));
    assert!(compact[not_found..throttled].contains("MissingDiagnostic::Absent"));

    let uncertainty = &compact[throttled..staged];
    assert!(uncertainty.contains("| (ProviderAttemptOutcome::Ambiguous, _)"));
    assert!(uncertainty.contains("Err(StoreError::from(SlowDown))"));
    assert!(
        !uncertainty.contains("mark_coordinated_missing"),
        "an ambiguous or throttled GET cannot publish Missing"
    );
    assert_eq!(
        compact.matches("FragmentGetResponse::NotFound").count(),
        1,
        "NotFound must have one closed tuple-classification arm"
    );
}

#[test]
fn direct_put_bytes_reach_only_the_admitted_provider_token() {
    let immutable = source("src/store/immutable_store.rs");
    let issue = function(&immutable, "async fn issue_direct_put(");
    assert!(issue.contains("put_body: None"));
    assert!(issue.contains(".admit_put("));
    assert!(!issue.contains(".admit_operation("));
    assert!(issue.contains(".execute_direct_put(&mut ledger, request.payload)"));
    assert!(!issue.contains("payload.to_vec()"));
    assert!(!issue.contains("FragmentTransportOperation::Head"));
}

#[test]
fn ambiguous_conditional_put_verifies_once_by_unmetered_get_before_any_remote_or_missing_verdict() {
    let immutable = source("src/store/immutable_store.rs");
    let issue = function(&immutable, "async fn issue_direct_put(");
    assert_eq!(
        issue.matches(".verify_conditional_put(").count(),
        1,
        "the ambiguous/precondition branch must perform exactly one verification GET"
    );
    assert!(issue.contains("(ProviderAttemptOutcome::Ambiguous, _)"));
    assert!(issue.contains(
        "ProviderAttemptOutcome::Decisive,\n                FragmentTransportResponse::PutPreconditionFailed"
    ));

    let verify = function(&immutable, "async fn verify_conditional_put(");
    assert_eq!(verify.matches(".get(").count(), 1);
    assert!(verify.contains("object_key: manifest.object_key.clone()"));
    assert!(verify.contains("FragmentGetResponse::Found { bytes, metadata }"));
    assert!(verify.contains("from_object_metadata(Some(&metadata))"));
    assert!(verify.contains(
        "Self::validate_candidate(address.hash, manifest, fragment, Bytes::from(bytes))"
    ));
    assert!(verify.contains("Ok(IoObservation::Valid(manifest.clone()))"));
    assert!(verify.contains("Ok(IoObservation::Unusable(diagnostic))"));
    assert!(verify.contains("Ok(IoObservation::Unusable(MissingDiagnostic::Absent))"));
    assert_verification_uncertainty_fails_closed(verify);
    for forbidden in [
        "FragmentAttemptLedger",
        "ProviderChargeAuthority",
        "budget_pin",
        "deadline_unix_ms",
    ] {
        assert!(
            !verify.contains(forbidden),
            "verification GET must remain unmetered and must not name {forbidden:?}"
        );
    }

    let coordinated = function(&immutable, "async fn put_coordinated(");
    let provider_io = coordinated
        .find(".issue_direct_put(")
        .expect("conditional provider PUT");
    let remote_or_missing = coordinated[provider_io..]
        .find(".commit_remote(")
        .map(|offset| provider_io + offset)
        .expect("Remote/Missing lifecycle verdict");
    assert!(provider_io < remote_or_missing);
    assert!(coordinated.contains(".issue_direct_put(") && coordinated.contains(".await?;"));
    assert!(
        !coordinated.contains("IoObservation::Unusable(MissingDiagnostic::Absent)"),
        "only a decisive verification result may construct Absent"
    );

    let throttled_as_absent = verify.replacen(
        "| (ProviderAttemptOutcome::Ambiguous, _) => Err(StoreError::from(SlowDown))",
        "| (ProviderAttemptOutcome::Ambiguous, _) => Ok(IoObservation::Unusable(MissingDiagnostic::Absent))",
        1,
    );
    assert!(
        std::panic::catch_unwind(|| {
            assert_verification_uncertainty_fails_closed(&throttled_as_absent)
        })
        .is_err(),
        "negative control rewriting uncertainty as modeled absence must fail"
    );
}

#[test]
fn governed_provider_disables_sdk_retry_without_changing_the_legacy_client_policy() {
    let immutable = source("src/store/immutable_store.rs");
    let connect = function(&immutable, "pub async fn connect(");
    assert!(connect.contains("let http_settings = HttpClientSettings::default();"));
    assert!(
        !connect.contains("RetryMode::Disabled") && !connect.contains("RetryConfig::disabled()"),
        "legacy construction must retain lore-aws's prior resolved retry policy"
    );

    let governed = function(&immutable, "pub async fn with_fragment_provider(");
    assert!(governed.contains("if target.bucket != self.bucket"));
    assert!(governed.contains(".sdk_client()\n            .config()\n            .to_builder()"));
    assert!(governed.contains(".retry_config(RetryConfig::disabled())"));
    assert!(governed.contains("aws_sdk_s3::Client::from_conf(provider_config)"));
    assert!(
        !governed.contains("self.s3.sdk_client().clone()"),
        "the governed transport needs a distinct retry-disabled physical client"
    );
}

#[test]
fn governed_transport_attests_region_and_endpoint_from_the_cloned_sdk_config() {
    let immutable = source("src/store/immutable_store.rs");
    let governed = function(&immutable, "pub async fn with_fragment_provider(");
    assert!(governed.contains("let resolved_endpoint_url = self"));
    assert!(governed.contains(".s3\n            .resolved_endpoint_url()"));
    assert!(
        governed
            .contains(".ok_or(PostgresFragmentProviderActivationError::MissingResolvedEndpoint)")
    );
    assert!(governed.contains("&resolved_endpoint_url"));

    let transport = source("src/store/fragment_transport.rs");
    let constructor = function(&transport, "pub(crate) async fn new(");
    assert_resolved_client_attestation(constructor);

    let label_self_attestation = constructor
        .replace(
            "if resolved_region != target_region",
            "if target_region != target_region",
        )
        .replace(
            "if resolved_endpoint_host != target_endpoint_host",
            "if target_endpoint_host != target_endpoint_host",
        );
    assert!(
        std::panic::catch_unwind(|| assert_resolved_client_attestation(&label_self_attestation))
            .is_err(),
        "negative control replacing resolved values with labels must fail"
    );
}

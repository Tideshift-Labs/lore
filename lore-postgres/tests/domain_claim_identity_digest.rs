// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Independent Rust pin for CR-029's frozen claim-identity digest v1.
//!
//! Lore does not derive this digest in production. The platform mints it and
//! Lore stores and exact-matches the 32 supplied bytes. This suite therefore
//! hardcodes the contract literals and proves the independent Rust view of the
//! preimage, digest, and six-field mutation boundary.

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeInput;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeStatus;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

const DOMAIN: &[u8] = b"repository-operation-claim-identity-v1\0";
const ORG_UUID: [u8; 16] = [
    0x9f, 0x8b, 0x7c, 0x6d, 0x5e, 0x4f, 0x4a, 0x3b, 0x8c, 0x2d, 0x1e, 0x0f, 0x9a, 0x8b, 0x7c, 0x6d,
];
const PRINCIPAL_NAMESPACE: &[u8] = b"principal-v1\x001c3d5e7f-9a0b-4c2d-8e4f-6a7b8c9d0e1f";
const OPERATION_ID: [u8; 16] = [
    0x01, 0x91, 0x23, 0x45, 0x67, 0x89, 0x7a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
];
const AUTHORIZATION_ID: [u8; 16] = OPERATION_ID;
const AUTHORIZATION_REVISION: u64 = 2;
const VERIFICATION_NONCE: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const EXPECTED_PREIMAGE_HEX: &str = concat!(
    "7265706f7369746f72792d6f7065726174696f6e2d636c61696d2d6964656e746974792d763100",
    "9f8b7c6d5e4f4a3b8c2d1e0f9a8b7c6d",
    "000000317072696e636970616c2d76310031633364356537662d396130622d346332642d386534662d366137623863396430653166",
    "0191234567897abc8def0123456789ab",
    "0191234567897abc8def0123456789ab",
    "0000000000000002",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
);
const EXPECTED_DIGEST_HEX: &str =
    "0f1b2baecc9e2217092a6c835340fcee2a8af841b639e0389de4f5b4ee2860f2";

#[derive(Clone)]
struct ClaimIdentity {
    org_uuid: [u8; 16],
    principal_namespace: Vec<u8>,
    operation_id: [u8; 16],
    authorization_id: [u8; 16],
    authorization_revision: u64,
    verification_nonce: [u8; 32],
}

impl ClaimIdentity {
    fn golden() -> Self {
        Self {
            org_uuid: ORG_UUID,
            principal_namespace: PRINCIPAL_NAMESPACE.to_vec(),
            operation_id: OPERATION_ID,
            authorization_id: AUTHORIZATION_ID,
            authorization_revision: AUTHORIZATION_REVISION,
            verification_nonce: VERIFICATION_NONCE,
        }
    }

    fn preimage(&self) -> Vec<u8> {
        let namespace_length = u32::try_from(self.principal_namespace.len())
            .expect("the hardcoded namespace length fits u32");
        let mut preimage = Vec::with_capacity(180);
        preimage.extend_from_slice(DOMAIN);
        preimage.extend_from_slice(&self.org_uuid);
        preimage.extend_from_slice(&namespace_length.to_be_bytes());
        preimage.extend_from_slice(&self.principal_namespace);
        preimage.extend_from_slice(&self.operation_id);
        preimage.extend_from_slice(&self.authorization_id);
        preimage.extend_from_slice(&self.authorization_revision.to_be_bytes());
        preimage.extend_from_slice(&self.verification_nonce);
        preimage
    }

    fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.preimage()).as_bytes()
    }
}

fn one_field_mutations(identity: &ClaimIdentity) -> Vec<(&'static str, ClaimIdentity)> {
    let mut mutations = Vec::new();
    let mut changed = identity.clone();
    changed.org_uuid[0] ^= 0xff;
    mutations.push(("org_uuid", changed));
    let mut changed = identity.clone();
    changed.principal_namespace[13] ^= 0x01;
    mutations.push(("initiating_principal_namespace", changed));
    let mut changed = identity.clone();
    changed.operation_id[15] ^= 0x01;
    mutations.push(("operation_id", changed));
    let mut changed = identity.clone();
    changed.authorization_id[15] ^= 0x01;
    mutations.push(("authorization_id", changed));
    let mut changed = identity.clone();
    changed.authorization_revision += 1;
    mutations.push(("authorization_revision", changed));
    let mut changed = identity.clone();
    changed.verification_nonce[0] ^= 0xff;
    mutations.push(("verification_nonce", changed));
    mutations
}

#[test]
fn frozen_claim_identity_golden_has_the_exact_preimage_and_digest() {
    let identity = ClaimIdentity::golden();
    let preimage = identity.preimage();

    assert_eq!(preimage.len(), 180);
    assert_eq!(hex::encode(&preimage), EXPECTED_PREIMAGE_HEX);
    assert_eq!(hex::encode(identity.digest()), EXPECTED_DIGEST_HEX);
}

#[test]
fn every_frozen_claim_identity_field_changes_the_digest() {
    let identity = ClaimIdentity::golden();
    let expected = identity.digest();
    for (field, mutation) in one_field_mutations(&identity) {
        assert_ne!(
            mutation.digest(),
            expected,
            "mutating {field} must not preserve the claim-identity digest"
        );
    }
}

#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn every_one_field_digest_mutation_is_refused_against_the_prepared_fence() {
    let Ok(url) = std::env::var("LORE_TEST_PG_URL") else {
        eprintln!("LORE_TEST_PG_URL unset; live fence-binding test cannot run");
        return;
    };
    let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
        .await
        .expect("connect disposable domain store");
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("database clock");
    let duration = clock
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("database clock follows Unix epoch");
    let operation_id = Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        duration.as_secs(),
        duration.subsec_nanos(),
    ));
    let golden_digest = ClaimIdentity::golden().digest();
    let key = ReceiptKey {
        verified_issuer: format!("https://issuer.example/{:016x}", rand::random::<u64>()),
        authenticated_subject: "svc:claim-digest-test".to_string(),
        tenant_scope_key: rand::random::<[u8; 16]>().to_vec(),
        operation_id,
    };
    let binding = OperationBinding {
        method: "lore.domain.v1.test/ClaimDigestFence".to_string(),
        scope: rand::random::<[u8; 16]>().to_vec(),
        fingerprint_version: 1,
        fingerprint: rand::random::<[u8; 32]>().to_vec(),
        canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
    };
    let witness = AuthorizationWitness {
        authorization_id: operation_id.as_bytes().to_vec(),
        authorization_revision: 2,
        verification_nonce: VERIFICATION_NONCE.to_vec(),
        bound_fields_digest: rand::random::<[u8; 32]>().to_vec(),
        consumed_ticket_sha256: rand::random::<[u8; 32]>().to_vec(),
        expected_claim_identity_digest: golden_digest.to_vec(),
    };
    let prepared = store
        .domain_operation_prepare(&key, &binding, Some(&witness), None)
        .await
        .expect("prepare binds the golden digest into its fence");
    assert!(matches!(prepared, PrepareResult::Prepared { .. }));

    for (field, mutation) in one_field_mutations(&ClaimIdentity::golden()) {
        let input = VerifiedStaleFinalizeInput {
            key: key.clone(),
            binding: binding.clone(),
            witness: witness.clone(),
            expected_claim_identity_digest: mutation.digest().to_vec(),
            stale_finalize_permit: rand::random::<[u8; 32]>().to_vec(),
            stale_finalize_permit_revision: 1,
            permit_verification_digest: rand::random::<[u8; 32]>().to_vec(),
        };
        let rejected = store
            .domain_operation_verified_stale_finalize(&input)
            .await
            .unwrap_or_else(|error| panic!("{field} mutation must be decisive: {error:?}"));
        assert_eq!(
            rejected.status,
            VerifiedStaleFinalizeStatus::Mismatch,
            "the prepared fence must refuse the digest produced by changing {field}"
        );
    }
    let exact = VerifiedStaleFinalizeInput {
        key,
        binding,
        witness,
        expected_claim_identity_digest: golden_digest.to_vec(),
        stale_finalize_permit: rand::random::<[u8; 32]>().to_vec(),
        stale_finalize_permit_revision: 1,
        permit_verification_digest: rand::random::<[u8; 32]>().to_vec(),
    };
    let exact = store
        .domain_operation_verified_stale_finalize(&exact)
        .await
        .expect("exact golden digest remains readable after rejected mutations");
    assert_eq!(
        exact.status,
        VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible,
        "rejected digest mutations must not alter the prepared fence"
    );
}

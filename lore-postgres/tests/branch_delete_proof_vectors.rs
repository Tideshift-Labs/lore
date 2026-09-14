// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Independent test-only implementation of the ratified branch-delete proof v1.
//! Pins the independent oracle and the production producer to cross-language bytes.

use lore_postgres::domain::delete_proof::DeleteProofReceipt;
use lore_postgres::domain::delete_proof::branch_delete_preimage;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::ReceiptKey;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/branch-delete-proof-v1.json");
const DOMAIN: &[u8] = b"lore-branch-delete-proof-v1\0";

fn string<'a>(vector: &'a Value, field: &str) -> &'a str {
    vector[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} must be a string"))
}

fn bytes(vector: &Value, field: &str, width: Option<usize>) -> Vec<u8> {
    let result = hex::decode(string(vector, field))
        .unwrap_or_else(|error| panic!("invalid {field} hex: {error}"));
    if let Some(width) = width {
        assert_eq!(result.len(), width, "{field} width");
    }
    result
}

fn framed(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("framed field must fit u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn preimage(vector: &Value) -> Vec<u8> {
    let mut output = DOMAIN.to_vec();
    framed(&mut output, string(vector, "verifiedIssuer").as_bytes());
    framed(
        &mut output,
        string(vector, "authenticatedSubject").as_bytes(),
    );
    framed(&mut output, &bytes(vector, "tenantScopeKeyHex", None));
    framed(&mut output, &bytes(vector, "operationIdHex", Some(16)));
    framed(&mut output, string(vector, "method").as_bytes());
    framed(&mut output, &bytes(vector, "canonicalScopeHex", None));
    let version = u32::try_from(
        vector["fingerprintVersion"]
            .as_u64()
            .expect("fingerprintVersion must be an unsigned integer"),
    )
    .expect("fingerprintVersion must fit u32");
    output.extend_from_slice(&version.to_be_bytes());
    framed(&mut output, &bytes(vector, "fingerprintHex", Some(32)));
    framed(
        &mut output,
        &bytes(vector, "canonicalIntentDigestHex", Some(32)),
    );
    match vector
        .get("clientAttemptIdHex")
        .expect("clientAttemptIdHex is required")
    {
        Value::Null => output.push(0),
        Value::String(_) => {
            output.push(1);
            output.extend_from_slice(&bytes(vector, "clientAttemptIdHex", Some(16)));
        }
        _ => panic!("clientAttemptIdHex must be null or a hex string"),
    }
    output.extend_from_slice(&bytes(vector, "repositoryIdHex", Some(16)));
    output.extend_from_slice(&bytes(vector, "branchIdHex", Some(16)));
    for field in [
        "repositoryGeneration",
        "priorGeneration",
        "committedGeneration",
    ] {
        let generation = string(vector, field)
            .parse::<u64>()
            .unwrap_or_else(|error| panic!("{field} must be a decimal u64: {error}"));
        output.extend_from_slice(&generation.to_be_bytes());
    }
    output.extend_from_slice(&bytes(vector, "finalLatestHashHex", Some(32)));
    output
}

#[test]
fn branch_delete_proof_v1_matches_every_golden_preimage_and_digest() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("valid golden JSON");
    assert_eq!(fixture["version"].as_u64(), Some(1));
    let vectors = fixture["vectors"].as_array().expect("vectors array");
    assert!(
        vectors.len() >= 5,
        "the full edge-case catalog must be present"
    );
    let mut names = std::collections::HashSet::new();
    for vector in vectors {
        let name = string(vector, "name");
        assert!(names.insert(name), "duplicate vector name: {name}");
        let actual = preimage(vector);
        let key = ReceiptKey {
            verified_issuer: string(vector, "verifiedIssuer").to_owned(),
            authenticated_subject: string(vector, "authenticatedSubject").to_owned(),
            tenant_scope_key: bytes(vector, "tenantScopeKeyHex", None),
            operation_id: uuid::Uuid::from_slice(&bytes(vector, "operationIdHex", Some(16)))
                .unwrap(),
        };
        let binding = OperationBinding {
            method: string(vector, "method").to_owned(),
            scope: bytes(vector, "canonicalScopeHex", None),
            fingerprint_version: vector["fingerprintVersion"]
                .as_i64()
                .unwrap()
                .try_into()
                .unwrap(),
            fingerprint: bytes(vector, "fingerprintHex", Some(32)),
            canonical_intent_digest: bytes(vector, "canonicalIntentDigestHex", Some(32)),
        };
        let attempt = vector["clientAttemptIdHex"]
            .as_str()
            .map(|_| bytes(vector, "clientAttemptIdHex", Some(16)));
        let receipt = DeleteProofReceipt {
            key: &key,
            binding: &binding,
            client_attempt_id: attempt.as_deref(),
        };
        let produced = branch_delete_preimage(
            &receipt,
            &bytes(vector, "repositoryIdHex", Some(16)),
            &bytes(vector, "branchIdHex", Some(16)),
            string(vector, "repositoryGeneration").parse().unwrap(),
            string(vector, "priorGeneration").parse().unwrap(),
            string(vector, "committedGeneration").parse().unwrap(),
            &bytes(vector, "finalLatestHashHex", Some(32)),
        )
        .unwrap();
        assert_eq!(
            produced, actual,
            "{name}: production versus independent encoder"
        );
        assert_eq!(
            actual,
            bytes(vector, "expectedPreimageHex", None),
            "{name}: preimage"
        );
        assert_eq!(
            blake3::hash(&actual).as_bytes().as_slice(),
            bytes(vector, "expectedProofHex", Some(32)),
            "{name}: proof"
        );
    }
}

#[test]
fn branch_delete_proof_rejects_malformed_fixed_width_fields() {
    let key = ReceiptKey {
        verified_issuer: "issuer".into(),
        authenticated_subject: "subject".into(),
        tenant_scope_key: vec![1; 16],
        operation_id: uuid::Uuid::new_v4(),
    };
    let binding = OperationBinding {
        method: "branch.delete".into(),
        scope: vec![2; 16],
        fingerprint_version: 1,
        fingerprint: vec![3; 32],
        canonical_intent_digest: vec![4; 32],
    };
    for width in [0, 15, 17] {
        let receipt = DeleteProofReceipt {
            key: &key,
            binding: &binding,
            client_attempt_id: None,
        };
        assert!(
            branch_delete_preimage(&receipt, &vec![0; width], &[1; 16], 1, 1, 2, &[2; 32]).is_err()
        );
        assert!(
            branch_delete_preimage(&receipt, &[0; 16], &vec![1; width], 1, 1, 2, &[2; 32]).is_err()
        );
        let attempt = vec![0; width];
        let receipt = DeleteProofReceipt {
            key: &key,
            binding: &binding,
            client_attempt_id: Some(&attempt),
        };
        assert!(branch_delete_preimage(&receipt, &[0; 16], &[1; 16], 1, 1, 2, &[2; 32]).is_err());
    }
    for width in [0, 31, 33] {
        let receipt = DeleteProofReceipt {
            key: &key,
            binding: &binding,
            client_attempt_id: None,
        };
        assert!(
            branch_delete_preimage(&receipt, &[0; 16], &[1; 16], 1, 1, 2, &vec![2; width]).is_err()
        );
    }
}

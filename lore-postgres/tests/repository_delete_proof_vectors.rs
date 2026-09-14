// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Independent test-only implementation of the ratified repository-delete proof v1.
//! This pins cross-language bytes; it does not add a production proof producer.

use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/repository-delete-proof-v1.json");
const DOMAIN: &[u8] = b"lore-repository-delete-proof-v1\0";

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
    for field in ["priorGeneration", "committedGeneration"] {
        let generation = string(vector, field)
            .parse::<u64>()
            .unwrap_or_else(|error| panic!("{field} must be a decimal u64: {error}"));
        output.extend_from_slice(&generation.to_be_bytes());
    }
    output
}

#[test]
fn repository_delete_proof_v1_matches_every_golden_preimage_and_digest() {
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

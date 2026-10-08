// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::event::LoreErrorCode;

/// Serde encodes an enum variant by its declaration index, not by its
/// explicit discriminant, and `LoreEvent` crosses the service boundary in
/// bitcode — a non-self-describing format. These bytes are the wire
/// contract: reorder the variants and a peer on an older build has its
/// payloads decode as different errors, silently. The discriminants are
/// free to change; the order is not. New variants go at the end.
#[test]
fn variant_order_is_pinned_to_the_wire_format() {
    for (variant, encoded) in [
        (LoreErrorCode::None, [0u8]),
        (LoreErrorCode::InvalidArguments, [1]),
        (LoreErrorCode::AddressNotFound, [2]),
        (LoreErrorCode::Internal, [3]),
        (LoreErrorCode::SlowDown, [4]),
    ] {
        assert_eq!(
            bitcode::serialize(&variant).expect("serialize"),
            encoded,
            "{variant:?} moved in declaration order; a payload from an \
                 older peer would decode as a different error"
        );
        let decoded: LoreErrorCode = bitcode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded, variant, "decoding {encoded:?} must be stable");
    }
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

mod raw_field_tests {
    use lore_server::grpc::domain::v1::strict_codec::validate_raw_fields;
    use lore_server::grpc::domain::v1::strict_codec::varint;

    #[test]
    fn varint_rule_above_tag_thirty_cannot_index_panic() {
        // tag 63, wire type 0 => key 504 => canonical varint f8 03.
        let raw = [0xf8, 0x03, 0x01];
        let (seen, values) = validate_raw_fields(&raw, &[varint(63)])
            .expect("a declared high varint tag must validate without indexing past the array");
        assert_eq!(seen, 1u64 << 63);
        assert_eq!(values[63], 1);
    }
}

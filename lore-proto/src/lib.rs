// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
// The included files do not pass this lint
#![allow(clippy::doc_markdown)]

#[rustfmt::skip]
#[path = "grpc/epic_urc.rs"]
pub mod auth;

// Nested to match proto package hierarchy. The generated lore.notification.rs uses
// super::super::urc::lock::Resource, which requires lock/model to be at crate::urc::*
// and notification to be at crate::lore::notification (two levels deep).
pub mod epic;
pub mod lore;
pub mod urc;

pub use urc::lock;
pub use urc::model;

#[rustfmt::skip]
#[path = "grpc/urc.rpc.rs"]
pub mod rpc;

#[rustfmt::skip]
#[path = "grpc/ucs.auth.rs"]
pub mod rebac;

mod convert;

pub use lock::lock_service_client::LockServiceClient;
pub use lock::lock_service_server::LockService;
pub use lock::lock_service_server::LockServiceServer;
pub use rebac::rebac_api_client::RebacApiClient;
pub use rpc::admin_service_client::AdminServiceClient;
pub use rpc::admin_service_server::AdminService;
pub use rpc::admin_service_server::AdminServiceServer;
pub use urc::model::*;

/// Prost codec for the private domain-operation service. Its decoder validates
/// the original protobuf message bytes for the four receipt-v2 maintenance
/// requests before Prost can discard unknown or duplicate singular fields.
#[derive(Debug, Clone, Default)]
pub struct DomainOperationV2StrictCodec<T, U>(std::marker::PhantomData<(T, U)>);

impl<T, U> tonic::codec::Codec for DomainOperationV2StrictCodec<T, U>
where
    T: prost::Message + Send + 'static,
    U: prost::Message + prost::Name + Default + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = tonic_prost::ProstEncoder<T>;
    type Decoder = DomainOperationV2StrictDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        tonic_prost::ProstEncoder::new(tonic::codec::BufferSettings::default())
    }

    fn decoder(&mut self) -> Self::Decoder {
        DomainOperationV2StrictDecoder::default()
    }
}

#[derive(Debug, Clone)]
pub struct DomainOperationV2StrictDecoder<U>(std::marker::PhantomData<U>);

impl<U> Default for DomainOperationV2StrictDecoder<U> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<U> tonic::codec::Decoder for DomainOperationV2StrictDecoder<U>
where
    U: prost::Message + prost::Name + Default,
{
    type Item = U;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        use prost::bytes::Buf as _;
        let raw = src.copy_to_bytes(src.remaining());
        validate_domain_operation_v2_raw(U::NAME, &raw)?;
        U::decode(raw)
            .map(Some)
            .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
    }
}

#[derive(Clone, Copy)]
enum DomainRawWire {
    Varint,
    LengthDelimited(usize),
}

#[derive(Clone, Copy)]
struct DomainRawField {
    tag: u32,
    wire: DomainRawWire,
}

const fn domain_ld(tag: u32, maximum: usize) -> DomainRawField {
    DomainRawField {
        tag,
        wire: DomainRawWire::LengthDelimited(maximum),
    }
}

const fn domain_varint(tag: u32) -> DomainRawField {
    DomainRawField {
        tag,
        wire: DomainRawWire::Varint,
    }
}

const fn domain_field_mask(tags: &[u32]) -> u64 {
    let mut mask = 0;
    let mut index = 0;
    while index < tags.len() {
        mask |= 1u64 << tags[index];
        index += 1;
    }
    mask
}

fn domain_read_varint(raw: &[u8], offset: &mut usize) -> Result<u64, tonic::Status> {
    let start = *offset;
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *raw
            .get(*offset)
            .ok_or_else(|| tonic::Status::invalid_argument("truncated protobuf varint"))?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            return Err(tonic::Status::invalid_argument("overflow protobuf varint"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let bits = 64usize.saturating_sub(value.leading_zeros() as usize);
            if *offset - start != bits.max(1).div_ceil(7) {
                return Err(tonic::Status::invalid_argument(
                    "noncanonical protobuf varint",
                ));
            }
            return Ok(value);
        }
    }
    Err(tonic::Status::invalid_argument("overflow protobuf varint"))
}

fn domain_validate_fields(
    raw: &[u8],
    rules: &[DomainRawField],
    required: u64,
) -> Result<(u64, [u64; 31]), tonic::Status> {
    if raw.len() > 16 * 1024 {
        return Err(tonic::Status::invalid_argument(
            "protobuf request exceeds 16384 bytes",
        ));
    }
    let mut offset = 0;
    let mut seen = 0u64;
    let mut values = [0u64; 31];
    while offset < raw.len() {
        let key = domain_read_varint(raw, &mut offset)?;
        let tag = u32::try_from(key >> 3)
            .map_err(|_| tonic::Status::invalid_argument("protobuf field tag overflows u32"))?;
        if tag == 0 || tag > 63 {
            return Err(tonic::Status::invalid_argument(
                "invalid protobuf field tag",
            ));
        }
        let rule = rules.iter().find(|rule| rule.tag == tag).ok_or_else(|| {
            tonic::Status::invalid_argument(format!("unknown protobuf field {tag}"))
        })?;
        let bit = 1u64 << tag;
        if seen & bit != 0 {
            return Err(tonic::Status::invalid_argument(format!(
                "duplicate singular protobuf field {tag}"
            )));
        }
        seen |= bit;
        match rule.wire {
            DomainRawWire::Varint => {
                if key & 7 != 0 {
                    return Err(tonic::Status::invalid_argument(format!(
                        "protobuf field {tag} has wrong wire type"
                    )));
                }
                values[tag as usize] = domain_read_varint(raw, &mut offset)?;
            }
            DomainRawWire::LengthDelimited(maximum) => {
                if key & 7 != 2 {
                    return Err(tonic::Status::invalid_argument(format!(
                        "protobuf field {tag} has wrong wire type"
                    )));
                }
                let length =
                    usize::try_from(domain_read_varint(raw, &mut offset)?).map_err(|_| {
                        tonic::Status::invalid_argument("protobuf length overflows usize")
                    })?;
                if length > maximum {
                    return Err(tonic::Status::invalid_argument(format!(
                        "protobuf field {tag} exceeds its canonical bound"
                    )));
                }
                offset = offset
                    .checked_add(length)
                    .filter(|end| *end <= raw.len())
                    .ok_or_else(|| {
                        tonic::Status::invalid_argument("truncated length-delimited field")
                    })?;
            }
        }
    }
    if seen & required != required {
        return Err(tonic::Status::invalid_argument(
            "protobuf request is missing required field presence",
        ));
    }
    Ok((seen, values))
}

/// Validate an original maintenance request payload by generated Prost name.
/// Other messages in the seven-method service are decoded normally.
pub fn validate_domain_operation_v2_raw(name: &str, raw: &[u8]) -> Result<(), tonic::Status> {
    const I: usize = 256;
    const U: usize = 16;
    const D: usize = 32;
    const P: usize = 49;
    const M: usize = 128;
    const S: usize = 4096;
    const J: usize = 8192;
    match name {
        "DomainOperationVerifiedStaleFinalizeRequest" => {
            let fields = [
                domain_ld(1, I),
                domain_ld(2, I),
                domain_ld(3, U),
                domain_ld(4, P),
                domain_ld(5, U),
                domain_ld(6, M),
                domain_ld(7, S),
                domain_varint(8),
                domain_ld(9, D),
                domain_ld(10, D),
                domain_ld(11, U),
                domain_varint(12),
                domain_ld(13, D),
                domain_ld(14, D),
                domain_ld(15, D),
                domain_ld(16, D),
                domain_ld(17, D),
                domain_varint(18),
            ];
            domain_validate_fields(
                raw,
                &fields,
                domain_field_mask(&[
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                ]),
            )?;
        }
        "DomainOperationTerminalStatusAttachRequest" => {
            let fields = [
                domain_ld(1, I),
                domain_ld(2, I),
                domain_ld(3, U),
                domain_ld(4, P),
                domain_ld(5, U),
                domain_ld(6, U),
                domain_varint(7),
                domain_ld(8, U),
                domain_varint(9),
                domain_varint(10),
                domain_ld(11, D),
                domain_varint(12),
                domain_varint(13),
                domain_varint(14),
                domain_varint(15),
                domain_ld(16, D),
                domain_varint(17),
                domain_ld(18, D),
                domain_varint(19),
                domain_ld(20, D),
                domain_varint(21),
                domain_ld(22, D),
                domain_ld(23, D),
                domain_varint(24),
                domain_ld(25, D),
                domain_varint(26),
                domain_ld(27, D),
                domain_varint(28),
                domain_ld(29, D),
                domain_ld(30, D),
            ];
            let base = domain_field_mask(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 21, 22, 26, 27, 28, 30,
            ]);
            let (seen, values) = domain_validate_fields(raw, &fields, base)?;
            match values[14] {
                1 if seen & domain_field_mask(&[17, 18, 19, 20, 23, 24, 25, 29]) == 0 => {}
                2 if seen & domain_field_mask(&[17, 18, 19, 20])
                    == domain_field_mask(&[17, 18, 19, 20]) =>
                {
                    match values[17] {
                        1 | 2 if seen & domain_field_mask(&[23, 24, 25, 29]) == 0 => {}
                        3 if seen & domain_field_mask(&[23, 24, 25, 29])
                            == domain_field_mask(&[23, 24, 25, 29]) => {}
                        _ => {
                            return Err(tonic::Status::invalid_argument(
                                "invalid Phase 2 action presence",
                            ));
                        }
                    }
                }
                _ => {
                    return Err(tonic::Status::invalid_argument(
                        "invalid terminal attach phase presence",
                    ));
                }
            }
        }
        "DomainOperationProofNamespaceMaterializeRequestV1" => {
            let fields = [
                domain_varint(1),
                domain_ld(2, I),
                domain_ld(3, I),
                domain_ld(4, U),
                domain_ld(5, P),
                domain_ld(6, U),
                domain_varint(7),
                domain_ld(8, D),
                domain_varint(9),
                domain_varint(10),
                domain_ld(11, D),
                domain_ld(12, J),
            ];
            domain_validate_fields(
                raw,
                &fields,
                domain_field_mask(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            )?;
        }
        "DomainOperationProofNamespaceRetireRequestV1" => {
            let fields = [
                domain_varint(1),
                domain_ld(2, I),
                domain_ld(3, I),
                domain_ld(4, U),
                domain_ld(5, P),
                domain_ld(6, U),
                domain_varint(7),
                domain_ld(8, D),
                domain_varint(9),
                domain_varint(10),
                domain_varint(11),
                domain_varint(12),
                domain_varint(13),
                domain_ld(14, D),
                domain_ld(15, D),
                domain_ld(16, J),
                domain_varint(17),
                domain_ld(18, D),
            ];
            domain_validate_fields(
                raw,
                &fields,
                domain_field_mask(&[
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                ]),
            )?;
        }
        _ => {}
    }
    Ok(())
}

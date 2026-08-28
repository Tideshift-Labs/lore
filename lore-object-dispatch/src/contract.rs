// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Crate-private canonical encoding primitives for source-dark contracts.

use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalPrimitiveError {
    InvalidText,
    InvalidUuidV7,
    InvalidMaximum,
    TooLarge,
}

pub(crate) fn validate_canonical_text(
    value: &str,
    maximum: u32,
) -> Result<(), CanonicalPrimitiveError> {
    if maximum == 0
        || value.is_empty()
        || value.len() > maximum as usize
        || value.contains('\0')
        || value.nfc().ne(value.chars())
    {
        return Err(CanonicalPrimitiveError::InvalidText);
    }
    Ok(())
}

pub(crate) fn decode_canonical_uuid_v7(value: &str) -> Result<[u8; 16], CanonicalPrimitiveError> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
        || bytes[14] != b'7'
        || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        || bytes.iter().enumerate().any(|(index, byte)| {
            !(matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f'))
        })
    {
        return Err(CanonicalPrimitiveError::InvalidUuidV7);
    }
    let mut decoded = [0u8; 16];
    for (nibble_index, byte) in bytes.iter().filter(|byte| **byte != b'-').enumerate() {
        let nibble = match byte {
            b'0'..=b'9' => *byte - b'0',
            b'a'..=b'f' => *byte - b'a' + 10,
            _ => return Err(CanonicalPrimitiveError::InvalidUuidV7),
        };
        let target = &mut decoded[nibble_index / 2];
        if nibble_index.is_multiple_of(2) {
            *target = nibble << 4;
        } else {
            *target |= nibble;
        }
    }
    Ok(decoded)
}

pub(crate) fn canonical_uuid_v7_timestamp(value: &str) -> Result<u64, CanonicalPrimitiveError> {
    let decoded = decode_canonical_uuid_v7(value)?;
    Ok(decoded[..6]
        .iter()
        .fold(0u64, |timestamp, byte| (timestamp << 8) | u64::from(*byte)))
}

pub(crate) struct BoundedCanonicalWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl BoundedCanonicalWriter {
    pub(crate) fn new(maximum: u32) -> Result<Self, CanonicalPrimitiveError> {
        if maximum == 0 {
            return Err(CanonicalPrimitiveError::InvalidMaximum);
        }
        Ok(Self {
            bytes: Vec::new(),
            maximum: maximum as usize,
        })
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(crate) fn raw(&mut self, value: &[u8]) -> Result<(), CanonicalPrimitiveError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(CanonicalPrimitiveError::TooLarge)?;
        if next > self.maximum {
            return Err(CanonicalPrimitiveError::TooLarge);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn u8(&mut self, value: u8) -> Result<(), CanonicalPrimitiveError> {
        self.raw(&[value])
    }

    pub(crate) fn u32(&mut self, value: u32) -> Result<(), CanonicalPrimitiveError> {
        self.raw(&value.to_be_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> Result<(), CanonicalPrimitiveError> {
        self.raw(&value.to_be_bytes())
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), CanonicalPrimitiveError> {
        let length = u32::try_from(value.len()).map_err(|_| CanonicalPrimitiveError::TooLarge)?;
        self.u32(length)?;
        self.raw(value)
    }

    pub(crate) fn text(&mut self, value: &str) -> Result<(), CanonicalPrimitiveError> {
        self.bytes(value.as_bytes())
    }
}

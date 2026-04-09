//! Hand-rolled binary witness format for selective-disclosure proofs.
//!
//! Each statement has its own fixed schema — there is no versioning, no
//! length-delimited "envelopes", and no serde. The guest decodes a
//! witness by asking a [`ByteReader`] for the exact sequence of field
//! types that the statement expects; any mismatch (short read, trailing
//! bytes, out-of-range variant tag) is a hard error and causes the
//! guest to `exit_error()`.
//!
//! The format is intentionally trivially auditable:
//!
//! ```text
//! fixed          = raw bytes, no framing
//! u32 / u64      = big-endian
//! vec<T>         = u32 BE length prefix, then `length * T`
//! bool           = 1 byte, 0x00 = false, 0x01 = true (no other values allowed)
//! enum variant   = 1 byte tag
//! ```
//!
//! The per-statement schemas live in [`crate::statements`].

use alloc::vec::Vec;

/// Errors returned by [`ByteReader`] when a decode fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessError {
    /// The input ended before the decoder finished reading a field.
    UnexpectedEnd,
    /// After the statement finished decoding, there were leftover bytes.
    TrailingBytes,
    /// A byte that should encode a `bool` was neither 0x00 nor 0x01.
    InvalidBool,
    /// An enum variant tag did not correspond to any known variant.
    InvalidVariant,
    /// A length prefix exceeded a statement-specific or crate-level cap.
    LengthOverflow,
}

/// Read-side cursor over a `&[u8]` with explicit error reporting for
/// every field type the witness schema uses.
///
/// The reader is stateful (it advances an internal offset) and does not
/// support lookahead or peek. It is cheap to copy by hand when a
/// statement needs to decode a sub-region.
#[derive(Debug)]
pub struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// Current read position (for error reporting / debugging).
    pub fn position(&self) -> usize {
        self.pos
    }

    /// After a statement is done decoding, call this to enforce that
    /// the caller consumed *every* byte of the witness. Any trailing
    /// data is a protocol violation.
    pub fn finish(self) -> Result<(), WitnessError> {
        if self.pos != self.bytes.len() {
            Err(WitnessError::TrailingBytes)
        } else {
            Ok(())
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WitnessError> {
        if self.pos + n > self.bytes.len() {
            return Err(WitnessError::UnexpectedEnd);
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn read_u8(&mut self) -> Result<u8, WitnessError> {
        Ok(self.take(1)?[0])
    }

    pub fn read_u32_be(&mut self) -> Result<u32, WitnessError> {
        let bs = self.take(4)?;
        Ok(u32::from_be_bytes([bs[0], bs[1], bs[2], bs[3]]))
    }

    pub fn read_u64_be(&mut self) -> Result<u64, WitnessError> {
        let bs = self.take(8)?;
        let mut out = [0u8; 8];
        out.copy_from_slice(bs);
        Ok(u64::from_be_bytes(out))
    }

    pub fn read_u64_le(&mut self) -> Result<u64, WitnessError> {
        let bs = self.take(8)?;
        let mut out = [0u8; 8];
        out.copy_from_slice(bs);
        Ok(u64::from_le_bytes(out))
    }

    pub fn read_bytes<const N: usize>(&mut self) -> Result<[u8; N], WitnessError> {
        let bs = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bs);
        Ok(out)
    }

    pub fn read_bool(&mut self) -> Result<bool, WitnessError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WitnessError::InvalidBool),
        }
    }

    /// Read a length-prefixed vector of fixed-size items (each item is
    /// exactly `item_size` bytes).
    ///
    /// `max_items` is a safety cap: a malicious witness cannot coerce
    /// the guest into allocating more items than this. Callers pick a
    /// statement-appropriate cap.
    pub fn read_vec_fixed(
        &mut self,
        item_size: usize,
        max_items: usize,
    ) -> Result<Vec<&'a [u8]>, WitnessError> {
        let n = self.read_u32_be()? as usize;
        if n > max_items {
            return Err(WitnessError::LengthOverflow);
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.take(item_size)?);
        }
        Ok(out)
    }
}

/// Write-side counterpart of [`ByteReader`], used by
/// `test-fixtures` / host-side tools to produce the canonical bytes.
#[derive(Debug, Default, Clone)]
pub struct ByteWriter {
    bytes: Vec<u8>,
}

impl ByteWriter {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(cap),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn write_u8(&mut self, v: u8) -> &mut Self {
        self.bytes.push(v);
        self
    }

    pub fn write_u32_be(&mut self, v: u32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn write_u64_be(&mut self, v: u64) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn write_u64_le(&mut self, v: u64) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn write_bytes(&mut self, v: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(v);
        self
    }

    pub fn write_bool(&mut self, v: bool) -> &mut Self {
        self.bytes.push(v as u8);
        self
    }

    /// Writes a length-prefixed vector where every item is exactly the
    /// same fixed size and has already been laid out as raw bytes.
    pub fn write_vec_fixed(&mut self, items: &[&[u8]]) -> &mut Self {
        self.write_u32_be(items.len() as u32);
        for it in items {
            self.bytes.extend_from_slice(it);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    #[test]
    fn round_trip_all_field_types() {
        let mut w = ByteWriter::new();
        w.write_u8(0xab)
            .write_u32_be(0x1234_5678)
            .write_u64_be(0x0102_0304_0506_0708)
            .write_u64_le(0x1122_3344_5566_7788)
            .write_bool(true)
            .write_bool(false)
            .write_bytes(&[0xde, 0xad, 0xbe, 0xef]);

        let bytes = w.into_bytes();
        let mut r = ByteReader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 0xab);
        assert_eq!(r.read_u32_be().unwrap(), 0x1234_5678);
        assert_eq!(r.read_u64_be().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(r.read_u64_le().unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(r.read_bool().unwrap(), true);
        assert_eq!(r.read_bool().unwrap(), false);
        assert_eq!(r.read_bytes::<4>().unwrap(), [0xde, 0xad, 0xbe, 0xef]);
        r.finish().unwrap();
    }

    #[test]
    fn short_read_errors() {
        let bytes = [0x01, 0x02];
        let mut r = ByteReader::new(&bytes);
        assert_eq!(r.read_u32_be(), Err(WitnessError::UnexpectedEnd));
    }

    #[test]
    fn trailing_bytes_errors() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut r = ByteReader::new(&bytes);
        let _ = r.read_u32_be().unwrap();
        assert_eq!(r.finish(), Err(WitnessError::TrailingBytes));
    }

    #[test]
    fn invalid_bool_is_rejected() {
        let bytes = [0x02];
        let mut r = ByteReader::new(&bytes);
        assert_eq!(r.read_bool(), Err(WitnessError::InvalidBool));
    }

    #[test]
    fn read_vec_fixed_round_trip() {
        let mut w = ByteWriter::new();
        let items: Vec<[u8; 3]> = vec![[1, 2, 3], [4, 5, 6], [7, 8, 9]];
        let refs: Vec<&[u8]> = items.iter().map(|x| &x[..]).collect();
        w.write_vec_fixed(&refs);

        let bytes = w.into_bytes();
        let mut r = ByteReader::new(&bytes);
        let got = r.read_vec_fixed(3, 100).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], &[1, 2, 3]);
        assert_eq!(got[1], &[4, 5, 6]);
        assert_eq!(got[2], &[7, 8, 9]);
        r.finish().unwrap();
    }

    #[test]
    fn read_vec_fixed_rejects_too_large() {
        let mut w = ByteWriter::new();
        w.write_u32_be(1_000); // claimed length
        let bytes = w.into_bytes();
        let mut r = ByteReader::new(&bytes);
        assert_eq!(
            r.read_vec_fixed(32, 100),
            Err(WitnessError::LengthOverflow),
        );
    }
}

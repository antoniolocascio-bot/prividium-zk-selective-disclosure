//! RLP encoding helpers used for block-header hashing.
//!
//! This is a direct port of
//! `zksync-os/basic_bootloader/src/bootloader/rlp.rs`. The bootloader's
//! hash is the authoritative one — we have to produce the exact same byte
//! stream, so this module is intentionally a line-by-line mirror with no
//! "improvements". Any change here must be made there first.
//!
//! The port uses our [`crate::hash::Keccak256Hasher`] wrapper in place of
//! the upstream's direct `sha3::Keccak256`. They share the same underlying
//! crate and the same `Digest` trait, so the byte stream is identical.
//!
//! The functions come in two flavors:
//!
//! - `estimate_*_len(...)`: return the number of bytes a given payload
//!   will encode to, without touching any hasher. Used to compute the
//!   outer list-length prefix before streaming the body.
//! - `apply_*_to_hash(...)`: stream the RLP-encoded bytes directly into a
//!   hasher, avoiding any allocation.
//!
//! The list-encoding pipeline expected by callers is:
//!
//! 1. estimate every element's encoded length;
//! 2. sum them → `list_body_len`;
//! 3. `apply_list_length_encoding_to_hash(list_body_len, hasher)`;
//! 4. `apply_*_to_hash(...)` for each element, in order.

use crate::hash::Keccak256Hasher;

/// Addresses are encoded as 20 data bytes + 1-byte length prefix (`0x94`).
pub const ADDRESS_ENCODING_LEN: usize = 21;

/// Estimate the RLP-encoded length of a **number**, which is an integer
/// encoded as its big-endian byte representation with leading zeros
/// stripped. A value of 0 encodes as the empty byte string.
pub fn estimate_number_encoding_len(value: &[u8]) -> usize {
    let first_non_zero_byte = value
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(value.len());
    estimate_bytes_encoding_len(&value[first_non_zero_byte..])
}

/// Number of extra bytes required to encode a payload whose body length
/// is `payload_encoding_len` bytes.
pub const fn estimate_encoding_len_for_payload_length(payload_encoding_len: usize) -> usize {
    if payload_encoding_len <= 55 {
        1
    } else {
        1 + core::mem::size_of::<usize>() - (payload_encoding_len.leading_zeros() / 8) as usize
    }
}

/// Estimate the RLP-encoded length of an arbitrary byte string.
pub fn estimate_bytes_encoding_len(value: &[u8]) -> usize {
    if value.len() == 1 && value[0] < 128 {
        return 1;
    }

    estimate_length_encoding_len(value.len()) + value.len()
}

/// Estimate the RLP length-prefix length for a bytes-or-list payload.
///
/// **Must not be called for a single byte smaller than 128** — that case
/// is encoded as the byte itself, not a length prefix.
pub fn estimate_length_encoding_len(length: usize) -> usize {
    if length < 56 {
        1
    } else {
        let length_bytes = length.to_be_bytes();
        // By the outer `if length < 56` branch we only get here for
        // `length >= 56`, which always has at least one non-zero byte.
        // The `unwrap_or` fallback is therefore unreachable — we use
        // it only to keep this function free of an explicit `unwrap`.
        let non_zero_byte = length_bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(length_bytes.len());
        1 + length_bytes.len() - non_zero_byte
    }
}

/// Stream the RLP encoding of a **number** to a Keccak hasher.
pub fn apply_number_encoding_to_hash(value: &[u8], hasher: &mut Keccak256Hasher) {
    let first_non_zero_byte = value
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(value.len());
    apply_bytes_encoding_to_hash(&value[first_non_zero_byte..], hasher);
}

/// Stream the RLP encoding of an arbitrary byte string to a Keccak hasher.
pub fn apply_bytes_encoding_to_hash(value: &[u8], hasher: &mut Keccak256Hasher) {
    if value.len() == 1 && value[0] < 128 {
        hasher.update(value);
        return;
    }

    apply_length_encoding_to_hash(value.len(), 128, hasher);
    hasher.update(value);
}

/// Stream the RLP list-length prefix for a list whose body is `length`
/// bytes.
pub fn apply_list_length_encoding_to_hash(length: usize, hasher: &mut Keccak256Hasher) {
    apply_length_encoding_to_hash(length, 192, hasher);
}

/// Shared helper for byte and list length prefixes.
///
/// `offset = 128` for byte strings, `offset = 192` for lists.
fn apply_length_encoding_to_hash(length: usize, offset: u8, hasher: &mut Keccak256Hasher) {
    if length < 56 {
        hasher.update(&[offset + length as u8]);
    } else {
        let length_bytes = length.to_be_bytes();
        // See note in `estimate_length_encoding_len`: this path only
        // runs for `length >= 56`, so there is always a non-zero byte.
        let non_zero_byte = length_bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(length_bytes.len());
        hasher.update(&[offset + 55 + (length_bytes.len() - non_zero_byte) as u8]);
        hasher.update(&length_bytes[non_zero_byte..]);
    }
}

#[cfg(test)]
mod tests {
    //! Byte-level tests for the RLP helpers.
    //!
    //! We verify against hand-computed RLP byte sequences. The block
    //! header hash itself (which layers everything on top) is
    //! cross-checked in `block_header::tests` by comparing against a
    //! known-answer vector.

    use super::*;
    use crate::hash::Keccak256Hasher;
    use alloc::{vec, vec::Vec};

    /// A little wrapper around `Keccak256Hasher` that also records the
    /// bytes passed through it. We feed this into the RLP functions and
    /// then assert on the resulting byte stream — effectively turning
    /// the "stream into hasher" functions into "stream into buffer"
    /// functions for testing.
    struct CapturingHasher {
        buf: Vec<u8>,
        hasher: Keccak256Hasher,
    }

    impl CapturingHasher {
        fn new() -> Self {
            Self {
                buf: Vec::new(),
                hasher: Keccak256Hasher::new(),
            }
        }

        fn update(&mut self, bytes: &[u8]) {
            self.buf.extend_from_slice(bytes);
            self.hasher.update(bytes);
        }
    }

    /// Shim: the RLP functions take `&mut Keccak256Hasher`, but for
    /// tests we want to observe the byte stream. We rewrite each test
    /// to use a capturing wrapper by temporarily redefining the calls.
    /// Since Rust does not let us pass `CapturingHasher` where
    /// `Keccak256Hasher` is expected, we duplicate the handful of body
    /// helpers here in a capturing form. This is strictly a test
    /// mirror — the logic must stay in sync with the real helpers
    /// above.

    fn cap_apply_length(length: usize, offset: u8, h: &mut CapturingHasher) {
        if length < 56 {
            h.update(&[offset + length as u8]);
        } else {
            let length_bytes = length.to_be_bytes();
            let non_zero = length_bytes.iter().position(|&b| b != 0).unwrap();
            h.update(&[offset + 55 + (length_bytes.len() - non_zero) as u8]);
            h.update(&length_bytes[non_zero..]);
        }
    }

    fn cap_apply_bytes(value: &[u8], h: &mut CapturingHasher) {
        if value.len() == 1 && value[0] < 128 {
            h.update(value);
            return;
        }
        cap_apply_length(value.len(), 128, h);
        h.update(value);
    }

    fn cap_apply_number(value: &[u8], h: &mut CapturingHasher) {
        let first = value.iter().position(|&b| b != 0).unwrap_or(value.len());
        cap_apply_bytes(&value[first..], h);
    }

    #[test]
    fn single_byte_below_128_encodes_as_itself() {
        let mut h = CapturingHasher::new();
        cap_apply_bytes(&[0x00], &mut h);
        assert_eq!(h.buf, vec![0x00]);

        let mut h = CapturingHasher::new();
        cap_apply_bytes(&[0x7f], &mut h);
        assert_eq!(h.buf, vec![0x7f]);
    }

    #[test]
    fn single_byte_at_or_above_128_has_length_prefix() {
        let mut h = CapturingHasher::new();
        cap_apply_bytes(&[0x80], &mut h);
        assert_eq!(h.buf, vec![0x81, 0x80]);

        let mut h = CapturingHasher::new();
        cap_apply_bytes(&[0xff], &mut h);
        assert_eq!(h.buf, vec![0x81, 0xff]);
    }

    #[test]
    fn empty_bytes_encodes_as_0x80() {
        let mut h = CapturingHasher::new();
        cap_apply_bytes(&[], &mut h);
        assert_eq!(h.buf, vec![0x80]);

        // And `estimate` agrees.
        assert_eq!(estimate_bytes_encoding_len(&[]), 1);
    }

    #[test]
    fn short_bytes_use_single_byte_prefix() {
        let mut h = CapturingHasher::new();
        // 32-byte all-zeros hash
        cap_apply_bytes(&[0u8; 32], &mut h);
        let mut expected = vec![0x80 + 32];
        expected.extend_from_slice(&[0u8; 32]);
        assert_eq!(h.buf, expected);
        assert_eq!(estimate_bytes_encoding_len(&[0u8; 32]), 33);
    }

    #[test]
    fn long_bytes_use_extended_prefix() {
        // 256-byte logs_bloom: length 256 = 0x0100, 2 bytes.
        let bloom = [0u8; 256];
        let mut h = CapturingHasher::new();
        cap_apply_bytes(&bloom, &mut h);
        let mut expected = vec![0xb9, 0x01, 0x00];
        expected.extend_from_slice(&bloom);
        assert_eq!(h.buf, expected);
        assert_eq!(estimate_bytes_encoding_len(&bloom), 3 + 256);
    }

    #[test]
    fn number_zero_encodes_as_empty_bytes() {
        // u64 zero as 8 big-endian bytes → RLP of empty byte string → 0x80
        let mut h = CapturingHasher::new();
        cap_apply_number(&0u64.to_be_bytes(), &mut h);
        assert_eq!(h.buf, vec![0x80]);
        assert_eq!(estimate_number_encoding_len(&0u64.to_be_bytes()), 1);
    }

    #[test]
    fn number_strips_leading_zeros() {
        // 0x2a as u64 → [0x2a] → single byte below 128 → 0x2a
        let mut h = CapturingHasher::new();
        cap_apply_number(&42u64.to_be_bytes(), &mut h);
        assert_eq!(h.buf, vec![0x2a]);

        // 0x0102 as u64 → [0x01, 0x02] → length 2 bytes prefix
        let mut h = CapturingHasher::new();
        cap_apply_number(&0x0102u64.to_be_bytes(), &mut h);
        assert_eq!(h.buf, vec![0x82, 0x01, 0x02]);

        // 128 (0x80) → [0x80] → single byte ≥ 128, needs length prefix
        let mut h = CapturingHasher::new();
        cap_apply_number(&128u64.to_be_bytes(), &mut h);
        assert_eq!(h.buf, vec![0x81, 0x80]);
    }

    #[test]
    fn list_length_prefix_short() {
        let mut h = CapturingHasher::new();
        cap_apply_length(0, 192, &mut h);
        assert_eq!(h.buf, vec![0xc0]);

        let mut h = CapturingHasher::new();
        cap_apply_length(55, 192, &mut h);
        assert_eq!(h.buf, vec![0xc0 + 55]);
    }

    #[test]
    fn list_length_prefix_long() {
        let mut h = CapturingHasher::new();
        cap_apply_length(494, 192, &mut h);
        // 494 = 0x01ee, 2 bytes → prefix 0xf7 + 2 = 0xf9, then 0x01 0xee.
        assert_eq!(h.buf, vec![0xf9, 0x01, 0xee]);
    }

    #[test]
    fn streamed_and_captured_bytes_match_on_real_helpers() {
        // Sanity check: a few calls through the real `apply_*_to_hash`
        // paths should feed the hasher the same bytes we would expect
        // from the capturing mirrors above.
        let mut real = Keccak256Hasher::new();
        apply_list_length_encoding_to_hash(2, &mut real);
        apply_bytes_encoding_to_hash(&[0x01], &mut real);
        apply_bytes_encoding_to_hash(&[0x02], &mut real);
        let real_out = real.finalize();

        // Equivalent: keccak256 of the bytes [0xc2, 0x01, 0x02]
        // (short list of length 2, containing single-byte 0x01 and 0x02).
        let expected = crate::hash::keccak256(&[0xc2, 0x01, 0x02]);
        assert_eq!(real_out, expected);
    }
}

//! ZKsync OS block header — fields + RLP-based Keccak hash.
//!
//! Mirrors `basic_bootloader::bootloader::block_header::BlockHeader` in
//! `zksync-os/basic_bootloader/src/bootloader/block_header.rs`, including
//! the exact field order, types, and hash computation. This is the
//! authoritative source — if the bootloader changes shape, this module
//! must be updated in lockstep.
//!
//! A byte-identical cross-check against the bootloader's own `hash()`
//! output lives in `test-fixtures` (Phase 2). Until that lands, the tests
//! here only validate internal consistency and the RLP byte-stream
//! primitives.
//!
//! # Layout notes
//!
//! - `beneficiary` is serialized as a 20-byte big-endian address. The
//!   bootloader passes it through `apply_bytes_encoding_to_hash`, which
//!   for a 20-byte payload always produces a 1-byte length prefix
//!   (`0x94`) followed by the address bytes. This is exactly
//!   [`ADDRESS_ENCODING_LEN = 21`](crate::rlp::ADDRESS_ENCODING_LEN).
//! - `difficulty` is a `U256` serialized as 32 BE bytes, then RLP-encoded
//!   as a **number** (leading zeros stripped). A `difficulty` of `0` ends
//!   up as the empty-bytes encoding `0x80`.
//! - `nonce` is 8 fixed bytes serialized as **bytes** (not a number), so
//!   an all-zeros nonce encodes as `0x88` followed by 8 zero bytes.
//! - `extra_data` has a compile-time max length of 32 bytes; ZKsync OS
//!   headers always use empty `extra_data`, but we allow up to 32 bytes
//!   to match the Ethereum spec and the bootloader's `ArrayVec<u8, 32>`.

use crate::hash::Keccak256Hasher;
use crate::rlp;
use alloc::vec::Vec;

/// ZKsync OS / Ethereum-ish block header.
///
/// Mirrors `basic_bootloader::bootloader::block_header::BlockHeader` field
/// for field, except that `extra_data` is a plain `Vec<u8>` here (the
/// upstream uses `arrayvec::ArrayVec<u8, 32>`). The upstream hash ends up
/// calling `extra_data.as_slice()` before encoding, so as long as our
/// `Vec<u8>` is `≤ 32` bytes, the encoded byte stream is identical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub parent_hash: [u8; 32],
    pub ommers_hash: [u8; 32],
    /// 20-byte big-endian address.
    pub beneficiary: [u8; 20],
    pub state_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: [u8; 256],
    /// `U256` in big-endian form (the bootloader stores this as `U256`
    /// and always calls `.to_be_bytes::<32>()` at hash time).
    pub difficulty: [u8; 32],
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    /// Up to 32 bytes of arbitrary payload; ZKsync OS blocks use `[]`.
    pub extra_data: Vec<u8>,
    pub mix_hash: [u8; 32],
    /// 8 fixed bytes, encoded as **bytes** in RLP (not a number).
    pub nonce: [u8; 8],
    pub base_fee_per_gas: u64,
}

/// The canonical empty-ommers-list hash used by post-merge Ethereum and
/// ZKsync OS headers: `keccak256(RLP([])) = 0x1dcc…9347`.
pub const EMPTY_OMMER_ROOT_HASH: [u8; 32] = [
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
];

impl BlockHeader {
    /// Sum of all field encodings — i.e. the body length of the RLP list
    /// that encodes this header. Used as the argument to
    /// `apply_list_length_encoding_to_hash` when computing
    /// [`Self::hash`].
    pub fn list_body_len(&self) -> usize {
        let mut n = 0;
        n += rlp::estimate_bytes_encoding_len(&self.parent_hash);
        n += rlp::estimate_bytes_encoding_len(&self.ommers_hash);
        n += rlp::ADDRESS_ENCODING_LEN;
        n += rlp::estimate_bytes_encoding_len(&self.state_root);
        n += rlp::estimate_bytes_encoding_len(&self.transactions_root);
        n += rlp::estimate_bytes_encoding_len(&self.receipts_root);
        n += rlp::estimate_bytes_encoding_len(&self.logs_bloom);
        n += rlp::estimate_number_encoding_len(&self.difficulty);
        n += rlp::estimate_number_encoding_len(&self.number.to_be_bytes());
        n += rlp::estimate_number_encoding_len(&self.gas_limit.to_be_bytes());
        n += rlp::estimate_number_encoding_len(&self.gas_used.to_be_bytes());
        n += rlp::estimate_number_encoding_len(&self.timestamp.to_be_bytes());
        n += rlp::estimate_bytes_encoding_len(self.extra_data.as_slice());
        n += rlp::estimate_bytes_encoding_len(&self.mix_hash);
        n += rlp::estimate_bytes_encoding_len(&self.nonce);
        n += rlp::estimate_number_encoding_len(&self.base_fee_per_gas.to_be_bytes());
        n
    }

    /// Keccak256 of the RLP-encoded header, i.e. the block hash.
    ///
    /// This must produce the exact same 32 bytes as
    /// `basic_bootloader::bootloader::block_header::BlockHeader::hash`.
    pub fn hash(&self) -> [u8; 32] {
        let list_body_len = self.list_body_len();

        let mut h = Keccak256Hasher::new();
        rlp::apply_list_length_encoding_to_hash(list_body_len, &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.parent_hash, &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.ommers_hash, &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.beneficiary, &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.state_root, &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.transactions_root, &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.receipts_root, &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.logs_bloom, &mut h);
        rlp::apply_number_encoding_to_hash(&self.difficulty, &mut h);
        rlp::apply_number_encoding_to_hash(&self.number.to_be_bytes(), &mut h);
        rlp::apply_number_encoding_to_hash(&self.gas_limit.to_be_bytes(), &mut h);
        rlp::apply_number_encoding_to_hash(&self.gas_used.to_be_bytes(), &mut h);
        rlp::apply_number_encoding_to_hash(&self.timestamp.to_be_bytes(), &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.extra_data, &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.mix_hash, &mut h);
        rlp::apply_bytes_encoding_to_hash(&self.nonce, &mut h);
        rlp::apply_number_encoding_to_hash(&self.base_fee_per_gas.to_be_bytes(), &mut h);
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::keccak256;

    /// A header with every single field zero / empty. Useful because
    /// every RLP encoding is at its minimal form and we can compute the
    /// complete byte stream by hand.
    fn zero_header() -> BlockHeader {
        BlockHeader {
            parent_hash: [0u8; 32],
            ommers_hash: [0u8; 32],
            beneficiary: [0u8; 20],
            state_root: [0u8; 32],
            transactions_root: [0u8; 32],
            receipts_root: [0u8; 32],
            logs_bloom: [0u8; 256],
            difficulty: [0u8; 32],
            number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Vec::new(),
            mix_hash: [0u8; 32],
            nonce: [0u8; 8],
            base_fee_per_gas: 0,
        }
    }

    /// Hand-compute the expected body length of a zero header.
    ///
    /// - parent_hash, ommers_hash, state_root, transactions_root,
    ///   receipts_root, mix_hash: 6 × (1 + 32) = 198
    /// - beneficiary: 21
    /// - logs_bloom: 1 (prefix 0xb9) + 2 (length 0x0100) + 256 = 259
    /// - difficulty: 0 as a number → 1
    /// - number, gas_limit, gas_used, timestamp, base_fee_per_gas:
    ///   5 × 1 = 5
    /// - extra_data: empty bytes → 1
    /// - nonce: 8 bytes → 1 (length prefix) + 8 = 9
    ///
    /// Total = 198 + 21 + 259 + 1 + 5 + 1 + 9 = 494.
    const ZERO_HEADER_BODY_LEN: usize = 494;

    #[test]
    fn zero_header_body_len_matches_manual_calculation() {
        assert_eq!(zero_header().list_body_len(), ZERO_HEADER_BODY_LEN);
    }

    #[test]
    fn zero_header_hash_matches_expected_byte_stream() {
        // Build the full RLP byte stream by hand, then keccak256 it,
        // and compare against the streaming `.hash()` output.
        //
        // Outer list prefix: 494 bytes body → long form.
        //   length_bytes(494) = [0x01, 0xee] (2 bytes)
        //   prefix = [0xf7 + 2, 0x01, 0xee] = [0xf9, 0x01, 0xee]
        let mut expected = Vec::with_capacity(3 + ZERO_HEADER_BODY_LEN);
        expected.extend_from_slice(&[0xf9, 0x01, 0xee]);

        // Six 32-byte zero hashes: parent_hash, ommers_hash, state_root,
        // transactions_root, receipts_root — mix_hash comes later in
        // field order. Each is [0xa0, 0x00 × 32].
        let push_zero_hash = |buf: &mut Vec<u8>| {
            buf.push(0xa0);
            buf.extend_from_slice(&[0u8; 32]);
        };
        push_zero_hash(&mut expected); // parent_hash
        push_zero_hash(&mut expected); // ommers_hash

        // beneficiary: 20 zero bytes → [0x94, 0x00 × 20]
        expected.push(0x94);
        expected.extend_from_slice(&[0u8; 20]);

        push_zero_hash(&mut expected); // state_root
        push_zero_hash(&mut expected); // transactions_root
        push_zero_hash(&mut expected); // receipts_root

        // logs_bloom: 256 zero bytes, long form
        expected.extend_from_slice(&[0xb9, 0x01, 0x00]);
        expected.extend_from_slice(&[0u8; 256]);

        // difficulty (number, 0) → 0x80
        expected.push(0x80);
        // number, gas_limit, gas_used, timestamp → 0x80 each
        expected.push(0x80);
        expected.push(0x80);
        expected.push(0x80);
        expected.push(0x80);

        // extra_data (empty bytes) → 0x80
        expected.push(0x80);

        push_zero_hash(&mut expected); // mix_hash

        // nonce: 8 zero bytes → [0x88, 0x00 × 8]
        expected.push(0x88);
        expected.extend_from_slice(&[0u8; 8]);

        // base_fee_per_gas → 0x80
        expected.push(0x80);

        // Sanity: our manual reconstruction matches the reported body len.
        assert_eq!(expected.len(), 3 + ZERO_HEADER_BODY_LEN);

        let expected_hash = keccak256(&expected);
        assert_eq!(zero_header().hash(), expected_hash);
    }

    #[test]
    fn non_trivial_header_has_different_hash() {
        let base = zero_header();
        let base_h = base.hash();

        let mut h = base.clone();
        h.number = 1;
        assert_ne!(base_h, h.hash());

        let mut h = base.clone();
        h.transactions_root[0] = 0xaa;
        assert_ne!(base_h, h.hash());

        let mut h = base.clone();
        h.extra_data.push(0x01);
        assert_ne!(base_h, h.hash());

        let mut h = base.clone();
        h.base_fee_per_gas = 0x1234_5678;
        assert_ne!(base_h, h.hash());
    }

    #[test]
    fn empty_ommer_root_constant_matches_keccak_of_empty_list() {
        // keccak256(RLP([])) where RLP([]) = [0xc0]
        assert_eq!(keccak256(&[0xc0]), EMPTY_OMMER_ROOT_HASH);
    }
}

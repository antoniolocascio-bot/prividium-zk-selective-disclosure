//! Public-input commitment.
//!
//! The single 32-byte value that the airbender guest commits as output
//! (the 8 `u32` words `x10..x17`) is always:
//!
//! ```text
//! pub_input = keccak256(
//!       statement_id.to_be_bytes(4)
//!    || batch_number.to_be_bytes(8)
//!    || l1_commitment                       // 32 bytes
//!    || statement_params                    // fixed length per statement
//! )
//! ```
//!
//! Keccak256 is chosen (not Blake2s) because the verifier side is native
//! Rust / Ethereum tooling, so prover-friendliness is irrelevant at this
//! boundary — what matters is that it is cheap to reproduce outside the
//! guest. The statement id goes first so that two statements with
//! accidentally identical trailing bytes cannot collide.
//!
//! See `DESIGN.md` §5 for the cross-statement parameter layouts, and
//! `params.rs` for the per-statement byte encodings.

use crate::hash::Keccak256Hasher;
use crate::params::{BalanceOfParams, ObservableBytecodeHashParams, TxInclusionParams};
use crate::statement_id::StatementId;

/// Length of the prefix that precedes the per-statement parameter bytes:
/// `statement_id (4) || batch_number (8) || l1_commitment (32) = 44`.
pub const HEADER_LEN: usize = 4 + 8 + 32;

/// Pack a 32-byte public-input commitment into the 8-word form
/// expected by the airbender `Commit` trait.
///
/// The packing is big-endian: byte `4*i .. 4*i+4` becomes word `i`.
/// The verifier reconstructs the bytes with [`unpack_from_words`].
pub const fn pack_to_words(pub_input: &[u8; 32]) -> [u32; 8] {
    let mut out = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = u32::from_be_bytes([
            pub_input[4 * i],
            pub_input[4 * i + 1],
            pub_input[4 * i + 2],
            pub_input[4 * i + 3],
        ]);
        i += 1;
    }
    out
}

/// Inverse of [`pack_to_words`] — reconstruct the 32 bytes from the
/// 8-word airbender receipt output.
pub const fn unpack_from_words(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 8 {
        let bytes = words[i].to_be_bytes();
        out[4 * i] = bytes[0];
        out[4 * i + 1] = bytes[1];
        out[4 * i + 2] = bytes[2];
        out[4 * i + 3] = bytes[3];
        i += 1;
    }
    out
}

/// Low-level helper: compute the public-input commitment over a raw,
/// fixed-length parameter byte slice.
///
/// Prefer the per-statement helpers below in callers — this exists so
/// the statement dispatcher and the fixture builder can share a single
/// code path.
pub fn compute_raw(
    statement_id: StatementId,
    batch_number: u64,
    l1_commitment: &[u8; 32],
    statement_params: &[u8],
) -> [u8; 32] {
    let mut h = Keccak256Hasher::new();
    h.update(&statement_id.to_u32().to_be_bytes());
    h.update(&batch_number.to_be_bytes());
    h.update(l1_commitment);
    h.update(statement_params);
    h.finalize()
}

/// Public-input commitment for a `balance_of` proof.
pub fn compute_balance_of(
    batch_number: u64,
    l1_commitment: &[u8; 32],
    params: &BalanceOfParams,
) -> [u8; 32] {
    compute_raw(
        StatementId::BalanceOf,
        batch_number,
        l1_commitment,
        &params.to_bytes(),
    )
}

/// Public-input commitment for an `observable_bytecode_hash` proof.
pub fn compute_observable_bytecode_hash(
    batch_number: u64,
    l1_commitment: &[u8; 32],
    params: &ObservableBytecodeHashParams,
) -> [u8; 32] {
    compute_raw(
        StatementId::ObservableBytecodeHash,
        batch_number,
        l1_commitment,
        &params.to_bytes(),
    )
}

/// Public-input commitment for a `tx_inclusion` proof.
pub fn compute_tx_inclusion(
    batch_number: u64,
    l1_commitment: &[u8; 32],
    params: &TxInclusionParams,
) -> [u8; 32] {
    compute_raw(
        StatementId::TxInclusion,
        batch_number,
        l1_commitment,
        &params.to_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::keccak256;
    use alloc::vec::Vec;

    #[test]
    fn header_len_is_four_plus_eight_plus_thirty_two() {
        assert_eq!(HEADER_LEN, 44);
    }

    #[test]
    fn compute_raw_matches_one_shot_keccak() {
        let batch_number = 0x1234_5678_9abc_def0u64;
        let l1 = [0xaau8; 32];
        let params: &[u8] = &[0x01, 0x02, 0x03];
        let got = compute_raw(StatementId::BalanceOf, batch_number, &l1, params);

        let mut buf = Vec::new();
        buf.extend_from_slice(&(StatementId::BalanceOf as u32).to_be_bytes());
        buf.extend_from_slice(&batch_number.to_be_bytes());
        buf.extend_from_slice(&l1);
        buf.extend_from_slice(params);
        let expected = keccak256(&buf);

        assert_eq!(got, expected);
    }

    #[test]
    fn statement_id_is_bound_into_commitment() {
        // Same params, different statement id → different commitment.
        let batch_number = 1u64;
        let l1 = [0u8; 32];
        let params: &[u8] = &[];
        let a = compute_raw(StatementId::BalanceOf, batch_number, &l1, params);
        let b = compute_raw(StatementId::ObservableBytecodeHash, batch_number, &l1, params);
        let c = compute_raw(StatementId::TxInclusion, batch_number, &l1, params);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn batch_number_is_bound_into_commitment() {
        let l1 = [0u8; 32];
        let params: &[u8] = &[];
        let a = compute_raw(StatementId::BalanceOf, 0, &l1, params);
        let b = compute_raw(StatementId::BalanceOf, 1, &l1, params);
        assert_ne!(a, b);
    }

    #[test]
    fn l1_commitment_is_bound_into_commitment() {
        let params: &[u8] = &[];
        let a = compute_raw(StatementId::BalanceOf, 0, &[0u8; 32], params);
        let mut l1 = [0u8; 32];
        l1[31] = 1;
        let b = compute_raw(StatementId::BalanceOf, 0, &l1, params);
        assert_ne!(a, b);
    }

    #[test]
    fn balance_of_helper_matches_raw() {
        let batch = 7u64;
        let l1 = [0xcdu8; 32];
        let params = BalanceOfParams {
            address: [0x01; 20],
            balance: [0x02; 32],
        };
        let via_helper = compute_balance_of(batch, &l1, &params);
        let via_raw = compute_raw(
            StatementId::BalanceOf,
            batch,
            &l1,
            &params.to_bytes(),
        );
        assert_eq!(via_helper, via_raw);
    }

    #[test]
    fn observable_helper_matches_raw() {
        let batch = 7u64;
        let l1 = [0xcdu8; 32];
        let params = ObservableBytecodeHashParams {
            address: [0x01; 20],
            observable_bytecode_hash: [0x02; 32],
        };
        let via_helper = compute_observable_bytecode_hash(batch, &l1, &params);
        let via_raw = compute_raw(
            StatementId::ObservableBytecodeHash,
            batch,
            &l1,
            &params.to_bytes(),
        );
        assert_eq!(via_helper, via_raw);
    }

    #[test]
    fn pack_unpack_round_trip() {
        let mut input = [0u8; 32];
        for i in 0..32 {
            input[i] = i as u8;
        }
        let words = pack_to_words(&input);
        // Check word[0] = 0x00010203 (big-endian) and word[7] = 0x1c1d1e1f.
        assert_eq!(words[0], 0x0001_0203);
        assert_eq!(words[7], 0x1c1d_1e1f);

        let unpacked = unpack_from_words(&words);
        assert_eq!(unpacked, input);
    }

    #[test]
    fn tx_inclusion_helper_matches_raw() {
        let batch = 7u64;
        let l1 = [0xcdu8; 32];
        let params = TxInclusionParams {
            block_number: 100,
            tx_hash: [0xff; 32],
        };
        let via_helper = compute_tx_inclusion(batch, &l1, &params);
        let via_raw = compute_raw(
            StatementId::TxInclusion,
            batch,
            &l1,
            &params.to_bytes(),
        );
        assert_eq!(via_helper, via_raw);
    }
}

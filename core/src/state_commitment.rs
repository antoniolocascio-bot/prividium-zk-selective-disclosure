//! ZKsync OS chain state commitment (`batchHash` in the on-chain
//! `StoredBatchInfo`).
//!
//! ```text
//! chain_state_commitment = blake2s(
//!       state_root                            // 32 bytes
//!    || next_free_slot.to_be_bytes(8)
//!    || block_number.to_be_bytes(8)
//!    || last_256_block_hashes_blake           // 32 bytes
//!    || last_block_timestamp.to_be_bytes(8)
//! )
//! ```
//!
//! Source:
//! - `zksync-os-server/docs/src/design/zks_getProof.md`
//!   § Verification → `computeStateCommitment`
//! - `zksync-os/basic_bootloader/src/bootloader/block_flow/zk/post_tx_op/public_input.rs`
//!   (`ChainStateCommitment::update`)
//!
//! The ordering (state_root || slot || block_number || 256-blob || ts) is
//! the authoritative one used by the bootloader when computing block/batch
//! public inputs.

use crate::hash::Blake2sHasher;

/// Preimage of the chain state commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainStateCommitment {
    pub state_root: [u8; 32],
    pub next_free_slot: u64,
    pub block_number: u64,
    /// `blake2s(concat of the last 256 block hashes, each as 32 bytes,
    /// oldest first)`. Computed by `TxInclusion` witnesses over the raw
    /// window.
    pub last_256_block_hashes_blake: [u8; 32],
    pub last_block_timestamp: u64,
}

impl ChainStateCommitment {
    /// Compute the Blake2s commitment.
    pub fn compute(&self) -> [u8; 32] {
        let mut h = Blake2sHasher::new();
        h.update(&self.state_root);
        h.update(&self.next_free_slot.to_be_bytes());
        h.update(&self.block_number.to_be_bytes());
        h.update(&self.last_256_block_hashes_blake);
        h.update(&self.last_block_timestamp.to_be_bytes());
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::blake2s_256;

    #[test]
    fn compute_matches_manual_concatenation() {
        let sc = ChainStateCommitment {
            state_root: [0x11; 32],
            next_free_slot: 0x22_22_22_22_22_22_22_22,
            block_number: 0x33_33_33_33_33_33_33_33,
            last_256_block_hashes_blake: [0x44; 32],
            last_block_timestamp: 0x55_55_55_55_55_55_55_55,
        };
        let got = sc.compute();

        let mut buf = [0u8; 32 + 8 + 8 + 32 + 8];
        buf[0..32].copy_from_slice(&sc.state_root);
        buf[32..40].copy_from_slice(&sc.next_free_slot.to_be_bytes());
        buf[40..48].copy_from_slice(&sc.block_number.to_be_bytes());
        buf[48..80].copy_from_slice(&sc.last_256_block_hashes_blake);
        buf[80..88].copy_from_slice(&sc.last_block_timestamp.to_be_bytes());
        let expected = blake2s_256(&buf);

        assert_eq!(got, expected);
    }

    #[test]
    fn field_changes_change_hash() {
        let base = ChainStateCommitment {
            state_root: [0u8; 32],
            next_free_slot: 1,
            block_number: 2,
            last_256_block_hashes_blake: [0u8; 32],
            last_block_timestamp: 3,
        };
        let base_h = base.compute();

        let mut mutated = base;
        mutated.block_number = 999;
        assert_ne!(base_h, mutated.compute());

        let mut mutated = base;
        mutated.state_root[0] = 1;
        assert_ne!(base_h, mutated.compute());

        let mut mutated = base;
        mutated.last_256_block_hashes_blake[31] = 1;
        assert_ne!(base_h, mutated.compute());
    }
}

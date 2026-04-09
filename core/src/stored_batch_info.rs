//! Reconstruction of ZKsync OS's on-chain `StoredBatchInfo` hash.
//!
//! The diamond proxy on L1 stores, for every committed batch, the value
//! `keccak256(abi.encode(StoredBatchInfo))`. This crate re-derives that
//! hash in-circuit so a proof can bind itself to an L1 commitment.
//!
//! # Solidity layout
//!
//! ```solidity
//! struct StoredBatchInfo {
//!     uint64  batchNumber;                 // @ word 0
//!     bytes32 batchHash;                   // @ word 1 (= chain_state_commitment in ZKsync OS)
//!     uint64  indexRepeatedStorageChanges; // @ word 2 (always 0 in ZKsync OS)
//!     uint256 numberOfLayer1Txs;           // @ word 3
//!     bytes32 priorityOperationsHash;      // @ word 4
//!     bytes32 dependencyRootsRollingHash;  // @ word 5
//!     bytes32 l2LogsTreeRoot;              // @ word 6
//!     uint256 timestamp;                   // @ word 7 (always 0 in ZKsync OS)
//!     bytes32 commitment;                  // @ word 8
//! }
//! ```
//!
//! Every field is ≤ 32 bytes, so the struct is entirely static and
//! `abi.encode(struct)` reduces to a simple 9-word, 288-byte
//! concatenation. `uint64` values are encoded as 32-byte big-endian
//! integers (zero-padded on the left).
//!
//! This matches the reference encoder in the ZKsync OS server's
//! `tools/verify-storage-proof` crate, which uses
//! `StoredBatchInfo::abi_encode_params()` from alloy's `sol!` macro. We
//! deliberately do the encoding by hand because:
//!
//! 1. alloy is a heavy `std` dependency we do not want in the `no_std`
//!    core crate, and
//! 2. the layout is trivial enough that a direct encoder is easier to
//!    audit than a macro expansion.

use crate::hash::{keccak256, Keccak256Hasher};

/// Fields of `StoredBatchInfo` that are *not* derived from a tree proof
/// (those come from `l1VerificationData` in `zks_getProof`, plus the two
/// constant-zero fields).
///
/// `batch_number`, `batch_hash` are supplied separately by the caller
/// because they come from different sources:
/// - `batch_hash` is the `ChainStateCommitment::compute()` output, which
///   the guest derived from a Merkle path;
/// - `batch_number` is a public parameter of the statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L1VerificationData {
    pub number_of_layer1_txs: [u8; 32],
    pub priority_operations_hash: [u8; 32],
    pub dependency_roots_rolling_hash: [u8; 32],
    pub l2_logs_tree_root: [u8; 32],
    pub commitment: [u8; 32],
}

/// Full reconstructed `StoredBatchInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredBatchInfo {
    pub batch_number: u64,
    pub batch_hash: [u8; 32],
    pub l1: L1VerificationData,
}

impl StoredBatchInfo {
    /// ABI-encoded byte length (9 × 32).
    pub const ENCODED_SIZE: usize = 9 * 32;

    /// Lay out the struct in the 288-byte static encoding and return it.
    ///
    /// This exists mainly for testing; callers generally prefer
    /// [`Self::compute_l1_commitment`] which streams the bytes straight
    /// into a Keccak hasher without an intermediate buffer.
    pub fn abi_encode(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut out = [0u8; Self::ENCODED_SIZE];

        // word 0: batchNumber (uint64) — right-aligned in 32 BE bytes
        out[24..32].copy_from_slice(&self.batch_number.to_be_bytes());

        // word 1: batchHash
        out[32..64].copy_from_slice(&self.batch_hash);

        // word 2: indexRepeatedStorageChanges — always 0

        // word 3: numberOfLayer1Txs (uint256)
        out[96..128].copy_from_slice(&self.l1.number_of_layer1_txs);

        // word 4: priorityOperationsHash
        out[128..160].copy_from_slice(&self.l1.priority_operations_hash);

        // word 5: dependencyRootsRollingHash
        out[160..192].copy_from_slice(&self.l1.dependency_roots_rolling_hash);

        // word 6: l2LogsTreeRoot
        out[192..224].copy_from_slice(&self.l1.l2_logs_tree_root);

        // word 7: timestamp — always 0

        // word 8: commitment
        out[256..288].copy_from_slice(&self.l1.commitment);

        out
    }

    /// `keccak256(abi.encode(StoredBatchInfo))`. This is the value that
    /// `diamondProxy.storedBatchHash(batchNumber)` returns on L1.
    pub fn compute_l1_commitment(&self) -> [u8; 32] {
        // Streaming form avoids the 288-byte stack buffer on the guest.
        let mut h = Keccak256Hasher::new();

        let mut word = [0u8; 32];

        // word 0
        word[24..].copy_from_slice(&self.batch_number.to_be_bytes());
        h.update(&word);
        word = [0u8; 32];

        // word 1
        h.update(&self.batch_hash);

        // word 2 (zero)
        h.update(&word);

        // word 3
        h.update(&self.l1.number_of_layer1_txs);

        // word 4
        h.update(&self.l1.priority_operations_hash);

        // word 5
        h.update(&self.l1.dependency_roots_rolling_hash);

        // word 6
        h.update(&self.l1.l2_logs_tree_root);

        // word 7 (zero)
        h.update(&word);

        // word 8
        h.update(&self.l1.commitment);

        h.finalize()
    }
}

/// Convenience wrapper: `keccak256(bytes)` so tests can hash the
/// `abi_encode` output directly.
#[inline]
pub fn keccak256_of(bytes: &[u8]) -> [u8; 32] {
    keccak256(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StoredBatchInfo {
        StoredBatchInfo {
            batch_number: 0x1234_5678_9abc_def0,
            batch_hash: [0x11; 32],
            l1: L1VerificationData {
                number_of_layer1_txs: {
                    let mut b = [0u8; 32];
                    b[31] = 5;
                    b
                },
                priority_operations_hash: [0x22; 32],
                dependency_roots_rolling_hash: [0x33; 32],
                l2_logs_tree_root: [0x44; 32],
                commitment: [0x55; 32],
            },
        }
    }

    #[test]
    fn encoded_size_is_288() {
        assert_eq!(StoredBatchInfo::ENCODED_SIZE, 288);
        assert_eq!(sample().abi_encode().len(), 288);
    }

    #[test]
    fn streamed_hash_matches_one_shot_hash() {
        let sb = sample();
        let streamed = sb.compute_l1_commitment();
        let one_shot = keccak256_of(&sb.abi_encode());
        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn word_layout_is_stable() {
        let sb = sample();
        let encoded = sb.abi_encode();

        // word 0: batchNumber left-padded
        assert_eq!(&encoded[0..24], &[0u8; 24]);
        assert_eq!(&encoded[24..32], &sb.batch_number.to_be_bytes());

        // word 1: batchHash
        assert_eq!(&encoded[32..64], &sb.batch_hash);

        // word 2: indexRepeatedStorageChanges = 0
        assert_eq!(&encoded[64..96], &[0u8; 32]);

        // word 3: numberOfLayer1Txs
        assert_eq!(&encoded[96..128], &sb.l1.number_of_layer1_txs);

        // word 4: priorityOperationsHash
        assert_eq!(&encoded[128..160], &sb.l1.priority_operations_hash);

        // word 5: dependencyRootsRollingHash
        assert_eq!(&encoded[160..192], &sb.l1.dependency_roots_rolling_hash);

        // word 6: l2LogsTreeRoot
        assert_eq!(&encoded[192..224], &sb.l1.l2_logs_tree_root);

        // word 7: timestamp = 0
        assert_eq!(&encoded[224..256], &[0u8; 32]);

        // word 8: commitment
        assert_eq!(&encoded[256..288], &sb.l1.commitment);
    }

    #[test]
    fn mutation_changes_hash() {
        let base = sample();
        let base_h = base.compute_l1_commitment();

        let mut m = base;
        m.batch_number += 1;
        assert_ne!(base_h, m.compute_l1_commitment());

        let mut m = base;
        m.batch_hash[0] ^= 1;
        assert_ne!(base_h, m.compute_l1_commitment());

        let mut m = base;
        m.l1.commitment[31] ^= 0xff;
        assert_ne!(base_h, m.compute_l1_commitment());
    }
}

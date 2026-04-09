//! On-wire types for ZKsync OS RPC responses we consume.
//!
//! These types mirror the JSON shape produced by
//! `zksync-os-server/lib/rpc_api/src/types.rs` and
//! `zksync-os-server/lib/merkle_tree_api/src/flat.rs` — specifically
//! [`BatchStorageProof`] (returned by `zks_getProof`) and its nested
//! Merkle-path shape. We redefine them here instead of depending on
//! the upstream crates because their transitive dep graph pulls in a
//! different version of `zksync-airbender` than our own
//! `airbender-host` dep, and the two cannot compile together.
//!
//! Any future drift in the upstream JSON wire format MUST be mirrored
//! here — the `rename_all = "camelCase"` plus `tag = "type"`
//! annotations are all that stand between us and silent decode
//! mismatches.
//!
//! Reference: upstream commit of
//! `zksync-os-server/lib/merkle_tree_api/src/flat.rs` as of PR #1161
//! (https://github.com/matter-labs/zksync-os-server/pull/1161).

use alloy::primitives::{Address, B256, U64};
use serde::{Deserialize, Serialize};

/// Information about a Merkle tree leaf sufficient — together with the
/// slot key — to recover the tree root hash.
///
/// Mirrors `zksync_os_merkle_tree_api::flat::StorageSlotProofEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageSlotProofEntry {
    pub index: u64,
    pub value: B256,
    pub next_index: u64,
    /// Merkle path to the slot in leaf-to-root order. May contain
    /// fewer than `tree_depth - 1` entries; missing trailing entries
    /// are implicitly hashes of empty subtrees at the corresponding
    /// depth.
    pub siblings: Vec<B256>,
}

/// A neighbor entry in a non-existence proof. Flattens
/// [`StorageSlotProofEntry`] and adds the neighbor's leaf key.
///
/// Mirrors `zksync_os_merkle_tree_api::flat::NeighborStorageSlotProofEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NeighborStorageSlotProofEntry {
    #[serde(flatten)]
    pub inner: StorageSlotProofEntry,
    pub leaf_key: B256,
}

/// The inner proof shape — either an existing-leaf proof, or a
/// bracketing pair of neighbor proofs proving non-existence.
///
/// Mirrors `zksync_os_merkle_tree_api::flat::InnerStorageSlotProof`.
/// The `#[serde(tag = "type", rename_all_fields = "camelCase")]`
/// matches the upstream on-wire layout exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum InnerStorageSlotProof {
    /// The slot is present in the tree.
    Existing(StorageSlotProofEntry),
    /// The slot is missing from the tree.
    NonExisting {
        left_neighbor: NeighborStorageSlotProofEntry,
        right_neighbor: NeighborStorageSlotProofEntry,
    },
}

/// Storage proof for a single slot together with the slot key that
/// allows standalone verification.
///
/// Mirrors `zksync_os_merkle_tree_api::flat::StorageSlotProof<K>`.
/// We always deserialize with `K = AddressScopedKey` because that is
/// what `zks_getProof` returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageSlotProof {
    /// Address-scoped key: the 32-byte storage key as passed to
    /// `zks_getProof`, before the flat-key derivation is applied.
    pub key: B256,
    pub proof: InnerStorageSlotProof,
}

/// Data hashed into the state commitment of the batch, alongside the
/// Merkle tree root hash.
///
/// Mirrors `zksync_os_rpc_api::types::StateCommitmentPreimage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateCommitmentPreimage {
    pub next_free_slot: U64,
    pub block_number: U64,
    pub last_256_block_hashes_blake: B256,
    pub last_block_timestamp: U64,
}

/// L1 verification data bundled into a `zks_getProof` response —
/// enough (together with the state commitment derived from the tree
/// proof) to reconstruct the on-chain `StoredBatchInfo` and check its
/// `keccak256(abi.encode(..))` against
/// `diamondProxy.storedBatchHash(batchNumber)`.
///
/// Mirrors `zksync_os_rpc_api::types::L1VerificationData`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct L1VerificationData {
    pub batch_number: u64,
    pub number_of_layer1_txs: u64,
    pub priority_operations_hash: B256,
    pub dependency_roots_rolling_hash: B256,
    pub l2_to_l1_logs_root_hash: B256,
    pub commitment: B256,
}

/// Full `zks_getProof` response.
///
/// Mirrors `zksync_os_rpc_api::types::BatchStorageProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchStorageProof {
    pub address: Address,
    pub state_commitment_preimage: StateCommitmentPreimage,
    pub storage_proofs: Vec<StorageSlotProof>,
    pub l1_verification_data: L1VerificationData,
}

#[cfg(test)]
mod tests {
    //! These tests lock in the exact JSON shape our decoder expects.
    //! If the upstream zks_getProof wire format changes, the snapshots
    //! here will fail and the mismatch can be fixed in one place.

    use super::*;
    use serde_json::json;

    #[test]
    fn existing_proof_entry_round_trip() {
        let entry = json!({
            "index": 42,
            "value": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "nextIndex": 99,
            "siblings": [
                "0x2222222222222222222222222222222222222222222222222222222222222222",
                "0x3333333333333333333333333333333333333333333333333333333333333333"
            ]
        });
        let decoded: StorageSlotProofEntry = serde_json::from_value(entry.clone()).unwrap();
        assert_eq!(decoded.index, 42);
        assert_eq!(decoded.next_index, 99);
        assert_eq!(decoded.siblings.len(), 2);
        let re_encoded = serde_json::to_value(&decoded).unwrap();
        assert_eq!(re_encoded, entry);
    }

    #[test]
    fn inner_storage_slot_proof_existing_tag() {
        let json_value = json!({
            "type": "existing",
            "index": 1,
            "value": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nextIndex": 2,
            "siblings": []
        });
        let decoded: InnerStorageSlotProof = serde_json::from_value(json_value).unwrap();
        assert!(matches!(decoded, InnerStorageSlotProof::Existing(_)));
    }

    #[test]
    fn inner_storage_slot_proof_non_existing_tag() {
        let json_value = json!({
            "type": "nonExisting",
            "leftNeighbor": {
                "index": 1,
                "value": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "nextIndex": 3,
                "siblings": [],
                "leafKey": "0x0000000000000000000000000000000000000000000000000000000000000001"
            },
            "rightNeighbor": {
                "index": 3,
                "value": "0x2222222222222222222222222222222222222222222222222222222222222222",
                "nextIndex": 1,
                "siblings": [],
                "leafKey": "0x00000000000000000000000000000000000000000000000000000000000000ff"
            }
        });
        let decoded: InnerStorageSlotProof = serde_json::from_value(json_value).unwrap();
        assert!(matches!(decoded, InnerStorageSlotProof::NonExisting { .. }));
    }

    #[test]
    fn state_commitment_preimage_camel_case() {
        let json_value = json!({
            "nextFreeSlot": "0x10",
            "blockNumber": "0x20",
            "last256BlockHashesBlake": "0x3333333333333333333333333333333333333333333333333333333333333333",
            "lastBlockTimestamp": "0x40"
        });
        let decoded: StateCommitmentPreimage = serde_json::from_value(json_value).unwrap();
        assert_eq!(decoded.next_free_slot, U64::from(0x10));
        assert_eq!(decoded.block_number, U64::from(0x20));
        assert_eq!(decoded.last_block_timestamp, U64::from(0x40));
    }
}

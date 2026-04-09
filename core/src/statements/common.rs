//! Shared witness-decoding helpers for the per-statement verifiers.
//!
//! All three statements need:
//!
//! - `ChainStateCommitment` preimage (5 fields),
//! - `L1VerificationData` (5 × 32 bytes),
//!
//! and two of them additionally need the Merkle-path decode for account
//! slots. Keeping these codecs in one place guarantees every statement
//! parses them identically.

use crate::state_commitment::ChainStateCommitment;
use crate::stored_batch_info::L1VerificationData;
use crate::tree::merkle::{AccountMerkleProof, FlatStorageLeaf, LeafProof, TREE_DEPTH};
use crate::witness::{ByteReader, ByteWriter, WitnessError};
use alloc::boxed::Box;

pub(crate) fn read_chain_state_commitment(
    r: &mut ByteReader<'_>,
) -> Result<ChainStateCommitment, WitnessError> {
    let state_root = r.read_bytes::<32>()?;
    let next_free_slot = r.read_u64_be()?;
    let block_number = r.read_u64_be()?;
    let last_256_block_hashes_blake = r.read_bytes::<32>()?;
    let last_block_timestamp = r.read_u64_be()?;
    Ok(ChainStateCommitment {
        state_root,
        next_free_slot,
        block_number,
        last_256_block_hashes_blake,
        last_block_timestamp,
    })
}

pub(crate) fn write_chain_state_commitment(w: &mut ByteWriter, c: &ChainStateCommitment) {
    w.write_bytes(&c.state_root)
        .write_u64_be(c.next_free_slot)
        .write_u64_be(c.block_number)
        .write_bytes(&c.last_256_block_hashes_blake)
        .write_u64_be(c.last_block_timestamp);
}

pub(crate) fn read_l1_verification_data(
    r: &mut ByteReader<'_>,
) -> Result<L1VerificationData, WitnessError> {
    Ok(L1VerificationData {
        number_of_layer1_txs: r.read_bytes::<32>()?,
        priority_operations_hash: r.read_bytes::<32>()?,
        dependency_roots_rolling_hash: r.read_bytes::<32>()?,
        l2_logs_tree_root: r.read_bytes::<32>()?,
        commitment: r.read_bytes::<32>()?,
    })
}

pub(crate) fn write_l1_verification_data(w: &mut ByteWriter, d: &L1VerificationData) {
    w.write_bytes(&d.number_of_layer1_txs)
        .write_bytes(&d.priority_operations_hash)
        .write_bytes(&d.dependency_roots_rolling_hash)
        .write_bytes(&d.l2_logs_tree_root)
        .write_bytes(&d.commitment);
}

pub(crate) fn read_leaf_proof(r: &mut ByteReader<'_>) -> Result<LeafProof, WitnessError> {
    let index = r.read_u64_be()?;
    let key = r.read_bytes::<32>()?;
    let value = r.read_bytes::<32>()?;
    let next = r.read_u64_be()?;

    // Path is always `TREE_DEPTH` entries, no length prefix — it is a
    // fixed-width field, not a vector. This matches `TestingTree`'s
    // uncompressed proof output.
    let mut path_arr = [[0u8; 32]; TREE_DEPTH];
    for slot in path_arr.iter_mut() {
        *slot = r.read_bytes::<32>()?;
    }
    Ok(LeafProof {
        index,
        leaf: FlatStorageLeaf { key, value, next },
        path: Box::new(path_arr),
    })
}

pub(crate) fn write_leaf_proof(w: &mut ByteWriter, p: &LeafProof) {
    w.write_u64_be(p.index)
        .write_bytes(&p.leaf.key)
        .write_bytes(&p.leaf.value)
        .write_u64_be(p.leaf.next);
    for sib in p.path.iter() {
        w.write_bytes(sib);
    }
}

/// Variant tag for the account-merkle-proof enum on the wire. Kept
/// explicit so the bitstream is auditable.
const EXISTING_TAG: u8 = 0;
const NON_EXISTING_TAG: u8 = 1;

pub(crate) fn read_account_merkle_proof(
    r: &mut ByteReader<'_>,
) -> Result<AccountMerkleProof, WitnessError> {
    match r.read_u8()? {
        EXISTING_TAG => Ok(AccountMerkleProof::Existing(read_leaf_proof(r)?)),
        NON_EXISTING_TAG => {
            let left = read_leaf_proof(r)?;
            let right = read_leaf_proof(r)?;
            Ok(AccountMerkleProof::NonExisting { left, right })
        }
        _ => Err(WitnessError::InvalidVariant),
    }
}

pub(crate) fn write_account_merkle_proof(w: &mut ByteWriter, p: &AccountMerkleProof) {
    match p {
        AccountMerkleProof::Existing(leaf) => {
            w.write_u8(EXISTING_TAG);
            write_leaf_proof(w, leaf);
        }
        AccountMerkleProof::NonExisting { left, right } => {
            w.write_u8(NON_EXISTING_TAG);
            write_leaf_proof(w, left);
            write_leaf_proof(w, right);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::blake2s_256;
    use crate::tree::merkle::TREE_DEPTH;

    fn sample_leaf() -> LeafProof {
        let mut path = [[0u8; 32]; TREE_DEPTH];
        for (i, s) in path.iter_mut().enumerate() {
            s[0] = i as u8;
        }
        LeafProof {
            index: 7,
            leaf: FlatStorageLeaf {
                key: [0xaa; 32],
                value: [0xbb; 32],
                next: 42,
            },
            path: Box::new(path),
        }
    }

    #[test]
    fn chain_state_commitment_round_trip() {
        let c = ChainStateCommitment {
            state_root: [0x01; 32],
            next_free_slot: 1234,
            block_number: 5678,
            last_256_block_hashes_blake: [0x02; 32],
            last_block_timestamp: 9999,
        };
        let mut w = ByteWriter::new();
        write_chain_state_commitment(&mut w, &c);
        let bytes = w.into_bytes();
        let mut r = ByteReader::new(&bytes);
        let got = read_chain_state_commitment(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(got, c);
    }

    #[test]
    fn l1_verification_data_round_trip() {
        let d = L1VerificationData {
            number_of_layer1_txs: [0x11; 32],
            priority_operations_hash: [0x22; 32],
            dependency_roots_rolling_hash: [0x33; 32],
            l2_logs_tree_root: [0x44; 32],
            commitment: [0x55; 32],
        };
        let mut w = ByteWriter::new();
        write_l1_verification_data(&mut w, &d);
        let bytes = w.into_bytes();
        let mut r = ByteReader::new(&bytes);
        let got = read_l1_verification_data(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(got, d);
    }

    #[test]
    fn leaf_proof_round_trip() {
        let p = sample_leaf();
        let mut w = ByteWriter::new();
        write_leaf_proof(&mut w, &p);
        let bytes = w.into_bytes();
        let mut r = ByteReader::new(&bytes);
        let got = read_leaf_proof(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(got.index, p.index);
        assert_eq!(got.leaf, p.leaf);
        assert_eq!(&got.path[..], &p.path[..]);
    }

    #[test]
    fn account_merkle_proof_existing_round_trip() {
        let proof = AccountMerkleProof::Existing(sample_leaf());
        let mut w = ByteWriter::new();
        write_account_merkle_proof(&mut w, &proof);
        let bytes = w.into_bytes();
        let mut r = ByteReader::new(&bytes);
        let got = read_account_merkle_proof(&mut r).unwrap();
        r.finish().unwrap();
        // Structural equality check by hash, to avoid adding Eq on
        // the whole enum / box.
        let expect_hash = blake2s_256(&w_bytes(&proof));
        let got_hash = blake2s_256(&w_bytes(&got));
        assert_eq!(expect_hash, got_hash);
    }

    #[test]
    fn account_merkle_proof_non_existing_round_trip() {
        let proof = AccountMerkleProof::NonExisting {
            left: sample_leaf(),
            right: sample_leaf(),
        };
        let mut w = ByteWriter::new();
        write_account_merkle_proof(&mut w, &proof);
        let bytes = w.into_bytes();
        let mut r = ByteReader::new(&bytes);
        let got = read_account_merkle_proof(&mut r).unwrap();
        r.finish().unwrap();
        let expect_hash = blake2s_256(&w_bytes(&proof));
        let got_hash = blake2s_256(&w_bytes(&got));
        assert_eq!(expect_hash, got_hash);
    }

    #[test]
    fn account_merkle_proof_rejects_bad_tag() {
        let mut bytes = alloc::vec::Vec::new();
        bytes.push(2u8); // invalid tag
        let mut r = ByteReader::new(&bytes);
        assert!(matches!(
            read_account_merkle_proof(&mut r),
            Err(WitnessError::InvalidVariant)
        ));
    }

    // Helper: serialize an AccountMerkleProof to bytes for hashing.
    fn w_bytes(p: &AccountMerkleProof) -> alloc::vec::Vec<u8> {
        let mut w = ByteWriter::new();
        write_account_merkle_proof(&mut w, p);
        w.into_bytes()
    }
}

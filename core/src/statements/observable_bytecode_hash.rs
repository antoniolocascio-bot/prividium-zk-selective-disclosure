//! `observable_bytecode_hash` statement verifier.
//!
//! Identical in shape to [`super::balance_of`], but the public-parameter
//! field checked against the decoded account preimage is
//! `observable_bytecode_hash` instead of `balance`.
//!
//! See `DESIGN.md` §6.2 for the verification logic.

use super::common::{
    read_account_merkle_proof, read_chain_state_commitment, read_l1_verification_data,
    write_account_merkle_proof, write_chain_state_commitment, write_l1_verification_data,
};
use super::StatementError;
use crate::account_properties::{AccountProperties, ENCODED_SIZE as ACCOUNT_PROPS_SIZE};
use crate::params::ObservableBytecodeHashParams;
use crate::pub_input;
use crate::state_commitment::ChainStateCommitment;
use crate::stored_batch_info::{L1VerificationData, StoredBatchInfo};
use crate::tree::key::account_properties_slot_key;
use crate::tree::merkle::{verify_account_proof, AccountMerkleProof};
use crate::witness::{ByteReader, ByteWriter};

/// Fully-decoded witness for an `observable_bytecode_hash` statement.
#[derive(Debug, Clone)]
pub struct ObservableBytecodeHashWitness {
    pub batch_number: u64,
    pub l1_commitment: [u8; 32],
    pub params: ObservableBytecodeHashParams,
    pub state_commitment: ChainStateCommitment,
    pub l1_verification_data: L1VerificationData,
    pub account_proof: AccountMerkleProof,
    pub account_properties_preimage: [u8; ACCOUNT_PROPS_SIZE],
}

impl ObservableBytecodeHashWitness {
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        let mut w = ByteWriter::new();
        w.write_u64_be(self.batch_number)
            .write_bytes(&self.l1_commitment)
            .write_bytes(&self.params.address)
            .write_bytes(&self.params.observable_bytecode_hash);
        write_chain_state_commitment(&mut w, &self.state_commitment);
        write_l1_verification_data(&mut w, &self.l1_verification_data);
        write_account_merkle_proof(&mut w, &self.account_proof);
        w.write_bytes(&self.account_properties_preimage);
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        let mut r = ByteReader::new(bytes);
        let batch_number = r.read_u64_be()?;
        let l1_commitment = r.read_bytes::<32>()?;
        let address = r.read_bytes::<20>()?;
        let observable_bytecode_hash = r.read_bytes::<32>()?;
        let state_commitment = read_chain_state_commitment(&mut r)?;
        let l1_verification_data = read_l1_verification_data(&mut r)?;
        let account_proof = read_account_merkle_proof(&mut r)?;
        let account_properties_preimage = r.read_bytes::<ACCOUNT_PROPS_SIZE>()?;
        r.finish()?;
        Ok(Self {
            batch_number,
            l1_commitment,
            params: ObservableBytecodeHashParams {
                address,
                observable_bytecode_hash,
            },
            state_commitment,
            l1_verification_data,
            account_proof,
            account_properties_preimage,
        })
    }
}

pub fn verify(bytes: &[u8]) -> Result<[u8; 32], StatementError> {
    let w = ObservableBytecodeHashWitness::decode(bytes)?;

    // 1. Verify Merkle proof and cross-check against the state
    //    commitment preimage.
    let flat_key = account_properties_slot_key(&w.params.address);
    let (state_root, stored_value) = verify_account_proof(&w.account_proof, &flat_key)?;
    if state_root != w.state_commitment.state_root {
        return Err(StatementError::StateRootMismatch);
    }

    // 2. Branch on proof variant.
    match &w.account_proof {
        AccountMerkleProof::Existing(_) => {
            let props = AccountProperties::decode(&w.account_properties_preimage);
            if stored_value != props.compute_hash() {
                return Err(StatementError::AccountPropertiesHashMismatch);
            }
            if props.observable_bytecode_hash != w.params.observable_bytecode_hash {
                return Err(StatementError::PublicParamMismatch);
            }
        }
        AccountMerkleProof::NonExisting { .. } => {
            // Non-existing account → implicit observable bytecode hash
            // is the all-zeros hash.
            if w.params.observable_bytecode_hash != [0u8; 32] {
                return Err(StatementError::NonExistingAccountClaim);
            }
        }
    }

    // 4. Recompute L1 commitment and match.
    let batch_hash = w.state_commitment.compute();
    let sbi = StoredBatchInfo {
        batch_number: w.batch_number,
        batch_hash,
        l1: w.l1_verification_data,
    };
    if sbi.compute_l1_commitment() != w.l1_commitment {
        return Err(StatementError::L1CommitmentMismatch);
    }

    // 5. Final public-input commitment.
    Ok(pub_input::compute_observable_bytecode_hash(
        w.batch_number,
        &w.l1_commitment,
        &w.params,
    ))
}

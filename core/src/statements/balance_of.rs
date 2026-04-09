//! `balance_of` statement verifier.
//!
//! Witness layout (all big-endian unless noted):
//!
//! ```text
//! BalanceOfParams {
//!     batch_number: u64,
//!     l1_commitment: [u8; 32],
//!     address: [u8; 20],
//!     balance: [u8; 32],
//! }
//! ChainStateCommitment { ... }           // 88 bytes
//! L1VerificationData   { ... }           // 160 bytes (5 × 32)
//! AccountMerkleProof   { ... }           // tag + leaves (+ 64 × 32 path each)
//! account_properties_preimage: [u8; 124]
//! ```
//!
//! See `DESIGN.md` §6.1 for the verification logic.

use super::common::{
    read_account_merkle_proof, read_chain_state_commitment, read_l1_verification_data,
    write_account_merkle_proof, write_chain_state_commitment, write_l1_verification_data,
};
use super::StatementError;
use crate::account_properties::{AccountProperties, ENCODED_SIZE as ACCOUNT_PROPS_SIZE};
use crate::params::BalanceOfParams;
use crate::pub_input;
use crate::state_commitment::ChainStateCommitment;
use crate::stored_batch_info::{L1VerificationData, StoredBatchInfo};
use crate::tree::key::account_properties_slot_key;
use crate::tree::merkle::{verify_account_proof, AccountMerkleProof};
use crate::witness::{ByteReader, ByteWriter};

/// Fully-decoded witness for a `balance_of` statement.
#[derive(Debug, Clone)]
pub struct BalanceOfWitness {
    pub batch_number: u64,
    pub l1_commitment: [u8; 32],
    pub params: BalanceOfParams,
    pub state_commitment: ChainStateCommitment,
    pub l1_verification_data: L1VerificationData,
    pub account_proof: AccountMerkleProof,
    pub account_properties_preimage: [u8; ACCOUNT_PROPS_SIZE],
}

impl BalanceOfWitness {
    /// Encode this witness to the canonical byte format that
    /// [`verify`] expects.
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        let mut w = ByteWriter::new();
        w.write_u64_be(self.batch_number)
            .write_bytes(&self.l1_commitment)
            .write_bytes(&self.params.address)
            .write_bytes(&self.params.balance);
        write_chain_state_commitment(&mut w, &self.state_commitment);
        write_l1_verification_data(&mut w, &self.l1_verification_data);
        write_account_merkle_proof(&mut w, &self.account_proof);
        w.write_bytes(&self.account_properties_preimage);
        w.into_bytes()
    }

    /// Decode from the canonical byte format, returning the statement-
    /// level error rather than the low-level witness error.
    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        let mut r = ByteReader::new(bytes);
        let batch_number = r.read_u64_be()?;
        let l1_commitment = r.read_bytes::<32>()?;
        let address = r.read_bytes::<20>()?;
        let balance = r.read_bytes::<32>()?;
        let state_commitment = read_chain_state_commitment(&mut r)?;
        let l1_verification_data = read_l1_verification_data(&mut r)?;
        let account_proof = read_account_merkle_proof(&mut r)?;
        let account_properties_preimage = r.read_bytes::<ACCOUNT_PROPS_SIZE>()?;
        r.finish()?;
        Ok(Self {
            batch_number,
            l1_commitment,
            params: BalanceOfParams { address, balance },
            state_commitment,
            l1_verification_data,
            account_proof,
            account_properties_preimage,
        })
    }
}

/// Statement verifier. On success returns the public-input commitment
/// to be committed by the guest; on failure returns a
/// [`StatementError`].
pub fn verify(bytes: &[u8]) -> Result<[u8; 32], StatementError> {
    let w = BalanceOfWitness::decode(bytes)?;

    // 1. Verify the Merkle proof and cross-check against the state
    //    commitment preimage. This establishes trust in
    //    `stored_value` before we look at the preimage.
    let flat_key = account_properties_slot_key(&w.params.address);
    let (state_root, stored_value) = verify_account_proof(&w.account_proof, &flat_key)?;
    if state_root != w.state_commitment.state_root {
        return Err(StatementError::StateRootMismatch);
    }

    // 2. Branch on proof variant.
    //
    //    For an **existing** account, the stored value must equal
    //    `blake2s(preimage)`, and the preimage's `balance` field must
    //    match the public `balance`.
    //
    //    For a **non-existing** account, the implicit balance is zero
    //    and the preimage supplied in the witness is unused. The
    //    public balance must be zero — otherwise the prover is
    //    claiming something about an account that does not exist.
    match &w.account_proof {
        AccountMerkleProof::Existing(_) => {
            let props = AccountProperties::decode(&w.account_properties_preimage);
            if stored_value != props.compute_hash() {
                return Err(StatementError::AccountPropertiesHashMismatch);
            }
            if props.balance != w.params.balance {
                return Err(StatementError::PublicParamMismatch);
            }
        }
        AccountMerkleProof::NonExisting { .. } => {
            if w.params.balance != [0u8; 32] {
                return Err(StatementError::NonExistingAccountClaim);
            }
        }
    }

    // 4. Rebuild the `chain_state_commitment` and assert it matches
    //    the `batchHash` field of the reconstructed `StoredBatchInfo`.
    let batch_hash = w.state_commitment.compute();
    let sbi = StoredBatchInfo {
        batch_number: w.batch_number,
        batch_hash,
        l1: w.l1_verification_data,
    };
    let computed_l1 = sbi.compute_l1_commitment();
    if computed_l1 != w.l1_commitment {
        return Err(StatementError::L1CommitmentMismatch);
    }

    // 5. Compute and return the public-input commitment.
    Ok(pub_input::compute_balance_of(
        w.batch_number,
        &w.l1_commitment,
        &w.params,
    ))
}

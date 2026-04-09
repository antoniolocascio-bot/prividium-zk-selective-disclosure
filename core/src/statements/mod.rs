//! Per-statement witness decoders and verifiers.
//!
//! Each submodule implements a `verify(bytes) -> Result<[u8; 32],
//! StatementError>` function that takes the raw witness bytes for its
//! statement and returns the public-input commitment on success. All
//! statements share a common decode-fail / logic-fail error enum so the
//! guest dispatcher can treat any failure uniformly (by calling
//! `exit_error()`).
//!
//! The dispatcher [`verify`] takes a [`StatementId`] plus a raw byte
//! slice and calls into the right submodule.

use crate::statement_id::StatementId;
use crate::tree::merkle::MerkleError;
use crate::witness::WitnessError;

mod common;

pub mod balance_of;
pub mod observable_bytecode_hash;
pub mod tx_inclusion;

/// All the ways a statement verification can fail.
///
/// The guest treats any `Err` as an exit-error and does not distinguish
/// between causes — but the variants are useful for unit tests on the
/// native side, where we want to assert that a specific tamper produces
/// a specific failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementError {
    /// The witness bytes did not decode.
    Witness(WitnessError),
    /// A Merkle proof inside the witness did not verify.
    Merkle(MerkleError),
    /// The Merkle proof verified, but its recomputed root did not match
    /// the root in the state-commitment preimage.
    StateRootMismatch,
    /// The account-properties hash in the tree did not match the
    /// Blake2s of the preimage supplied in the witness.
    AccountPropertiesHashMismatch,
    /// A non-existing account was supplied with a non-zero balance /
    /// non-zero bytecode hash claim.
    NonExistingAccountClaim,
    /// A public-parameter field did not match the value recovered from
    /// the witness (e.g. balance, address, bytecode hash).
    PublicParamMismatch,
    /// Blake2s over the 256-block window did not equal
    /// `state_commitment.last_256_block_hashes_blake`.
    WindowHashMismatch,
    /// `selected_block_index` was out of `[0, 256)` or referenced a
    /// block whose window entry did not match the claimed header hash.
    BlockWindowMismatch,
    /// The keccak256(RLP(block_header)) did not match the selected
    /// block hash from the window.
    BlockHashMismatch,
    /// `block_header.number` did not match
    /// `tip - 255 + selected_block_index`, or the public
    /// `block_number` did not match either.
    BlockNumberMismatch,
    /// Replayed `TransactionsRollingKeccakHasher` over
    /// `block_tx_hashes` did not equal `block_header.transactions_root`.
    TxRollingHashMismatch,
    /// `tx_index` was out of bounds for `block_tx_hashes`, or the tx
    /// at `tx_index` did not match the public `tx_hash`.
    TxIndexMismatch,
    /// The recomputed `keccak256(abi.encode(StoredBatchInfo))` did not
    /// match the public `l1_commitment`.
    L1CommitmentMismatch,
}

impl From<WitnessError> for StatementError {
    fn from(e: WitnessError) -> Self {
        Self::Witness(e)
    }
}

impl From<MerkleError> for StatementError {
    fn from(e: MerkleError) -> Self {
        Self::Merkle(e)
    }
}

/// Top-level dispatcher. Reads a `StatementId` tag and delegates to the
/// matching submodule.
pub fn verify(id: StatementId, bytes: &[u8]) -> Result<[u8; 32], StatementError> {
    match id {
        StatementId::BalanceOf => balance_of::verify(bytes),
        StatementId::ObservableBytecodeHash => observable_bytecode_hash::verify(bytes),
        StatementId::TxInclusion => tx_inclusion::verify(bytes),
    }
}

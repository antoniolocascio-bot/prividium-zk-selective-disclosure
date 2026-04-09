//! High-level request types.
//!
//! A [`DisclosureRequest`] is what a user of the library/CLI asks to
//! prove: "I want a proof that account X had balance Y at batch B", or
//! similar. The prover turns a `DisclosureRequest` into a
//! fully-formed [`crate::prover::ProveRequest`] — which already
//! contains the witness bytes — by going through a
//! [`crate::witness_source::WitnessSource`].
//!
//! Keeping the request types as a small enum here (rather than one
//! function per statement) makes it easy for a CLI binary to build a
//! request from command-line args and hand it off uniformly.

use alloy::primitives::{Address, B256};

/// What the user wants to prove. Mirrors the three v0 statements from
/// `DESIGN.md` one-to-one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisclosureRequest {
    /// Prove `balance_of(batch_number, l1_commitment, address, balance)`.
    BalanceOf {
        batch_number: u64,
        address: Address,
    },
    /// Prove `observable_bytecode_hash(batch_number, l1_commitment, address, hash)`.
    ObservableBytecodeHash {
        batch_number: u64,
        address: Address,
    },
    /// Prove `tx_inclusion(batch_number, l1_commitment, block_number, tx_hash)`.
    TxInclusion {
        batch_number: u64,
        tx_hash: B256,
    },
}

impl DisclosureRequest {
    pub fn batch_number(&self) -> u64 {
        match self {
            Self::BalanceOf { batch_number, .. }
            | Self::ObservableBytecodeHash { batch_number, .. }
            | Self::TxInclusion { batch_number, .. } => *batch_number,
        }
    }
}

//! Pluggable source for on-chain `storedBatchHash(batch_number)`.
//!
//! The verifier's trust root is the diamond proxy contract on the
//! settlement layer. Rather than hard-wire an L1 RPC client into the
//! verifier library, we abstract the lookup behind a tiny trait so
//! that:
//!
//! - Tests can supply an in-memory `MockL1Source` with a pre-baked
//!   commitment map (no network required).
//! - Future real impls can plug in an alloy/ethers provider without
//!   churning the verifier.
//!
//! The trait is deliberately minimal — just the one lookup. Fancier
//! sources (with caching, fallback providers, etc.) should wrap a
//! simpler source rather than extend the trait surface.

use std::collections::HashMap;

/// Something that can resolve `storedBatchHash(batch_number)` for
/// the Prividium's diamond proxy contract on L1.
pub trait L1Source {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Return the canonical `keccak256(abi.encode(StoredBatchInfo))`
    /// for the given L1 batch number, or an error if the batch has
    /// not been committed (or the source can't answer).
    fn stored_batch_hash(&self, batch_number: u64) -> Result<[u8; 32], Self::Error>;
}

/// In-memory implementation of [`L1Source`]. Used by tests to stub
/// out an L1 query with a fixed `batch_number → commitment` mapping.
#[derive(Clone, Debug, Default)]
pub struct MockL1Source {
    commitments: HashMap<u64, [u8; 32]>,
}

/// Errors a [`MockL1Source`] can produce.
#[derive(Debug, thiserror::Error)]
pub enum MockL1Error {
    #[error("no commitment registered for batch {0}")]
    MissingBatch(u64),
}

impl MockL1Source {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_batch(mut self, batch_number: u64, l1_commitment: [u8; 32]) -> Self {
        self.commitments.insert(batch_number, l1_commitment);
        self
    }

    pub fn insert(&mut self, batch_number: u64, l1_commitment: [u8; 32]) -> &mut Self {
        self.commitments.insert(batch_number, l1_commitment);
        self
    }
}

impl L1Source for MockL1Source {
    type Error = MockL1Error;

    fn stored_batch_hash(&self, batch_number: u64) -> Result<[u8; 32], Self::Error> {
        self.commitments
            .get(&batch_number)
            .copied()
            .ok_or(MockL1Error::MissingBatch(batch_number))
    }
}

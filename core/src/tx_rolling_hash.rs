//! Rolling Keccak-256 accumulator for transaction hashes — matches
//! the bootloader's `tx_rolling_hash` local variable in
//! `basic_bootloader::bootloader::run_prepared` (`bootloader/mod.rs`),
//! which is what ends up in a block header's `transactions_root`
//! field.
//!
//! ```text
//! state₀       = [0u8; 32]                 // zero-initialized!
//! state_{i+1}  = keccak256(state_i || tx_hash_i)
//! ```
//!
//! # Warning — two similar-but-distinct accumulators exist
//!
//! ZKsync OS has a separate type named
//! `TransactionsRollingKeccakHasher` in
//! `basic_bootloader/src/bootloader/block_flow/zk/block_data.rs`. That
//! one initializes its state to `keccak256("")` (i.e. `0xc5d2…a470`)
//! and is used to accumulate **priority-operation hashes** for the ZK
//! batch public input, NOT the block header's `transactions_root`.
//! The two are entirely separate accumulators with different initial
//! states — confusing them gives the wrong root for tx-inclusion
//! proofs.
//!
//! The one we want for tx-inclusion is the **zero-initialized** one,
//! because `tx_inclusion` binds to `block_header.transactions_root`.
//! See `bootloader/mod.rs:213` in the upstream bootloader for the
//! initial-state definition:
//!
//! ```rust,ignore
//! let mut tx_rolling_hash = [0u8; 32];
//! // ...
//! keccak.update(tx_rolling_hash);
//! keccak.update(tx_processing_result.tx_hash.as_u8_ref());
//! tx_rolling_hash = keccak.finalize();
//! ```

use crate::hash::Keccak256Hasher;

/// The initial state of the `transactions_root` rolling hash — all
/// zeros, matching `bootloader/mod.rs:213`.
pub const INITIAL_STATE: [u8; 32] = [0u8; 32];

/// Rolling Keccak-256 accumulator for in-block transaction hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxRollingHasher {
    state: [u8; 32],
    count: u32,
}

impl Default for TxRollingHasher {
    fn default() -> Self {
        Self::empty()
    }
}

impl TxRollingHasher {
    /// Fresh hasher, initial state `[0u8; 32]`. Matches the
    /// bootloader's `tx_rolling_hash = [0u8; 32]` initialization.
    pub fn empty() -> Self {
        Self {
            state: INITIAL_STATE,
            count: 0,
        }
    }

    /// Incorporate a single transaction hash.
    ///
    /// `state_{i+1} = keccak256(state_i || tx_hash_i)`.
    pub fn push(&mut self, tx_hash: &[u8; 32]) -> &mut Self {
        let mut h = Keccak256Hasher::new();
        h.update(&self.state);
        h.update(tx_hash);
        self.state = h.finalize();
        self.count += 1;
        self
    }

    /// Current accumulated rolling hash, without consuming `self`.
    pub fn current(&self) -> [u8; 32] {
        self.state
    }

    /// Number of transaction hashes fed in so far.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Convenience: roll up an ordered slice of hashes in one call.
    pub fn roll(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
        let mut r = Self::empty();
        for h in tx_hashes {
            r.push(h);
        }
        r.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::keccak256;

    #[test]
    fn empty_hasher_starts_at_zero() {
        assert_eq!(TxRollingHasher::empty().current(), [0u8; 32]);
        assert_eq!(INITIAL_STATE, [0u8; 32]);
    }

    #[test]
    fn single_push_matches_manual_form() {
        let tx = [0x42u8; 32];
        let mut r = TxRollingHasher::empty();
        r.push(&tx);
        assert_eq!(r.count(), 1);

        // Manually: keccak256([0u8; 32] || tx)
        let mut buf = [0u8; 64];
        buf[32..].copy_from_slice(&tx);
        assert_eq!(r.current(), keccak256(&buf));
    }

    #[test]
    fn roll_order_matters() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];

        let ab = TxRollingHasher::roll(&[a, b]);
        let ba = TxRollingHasher::roll(&[b, a]);
        assert_ne!(ab, ba);
    }

    #[test]
    fn roll_is_equivalent_to_iterated_pushes() {
        let tx_hashes = [
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
            [0x04u8; 32],
        ];
        let via_roll = TxRollingHasher::roll(&tx_hashes);

        let mut via_push = TxRollingHasher::empty();
        for h in &tx_hashes {
            via_push.push(h);
        }

        assert_eq!(via_roll, via_push.current());
        assert_eq!(via_push.count(), 4);
    }
}

//! Rolling Keccak-256 accumulator for transaction hashes.
//!
//! Mirrors `basic_bootloader::bootloader::block_flow::zk::block_data::
//! TransactionsRollingKeccakHasher` (`block_data.rs`). The bootloader
//! uses this accumulator to produce the `transactions_root` field of a
//! block header:
//!
//! ```text
//! state₀       = keccak256("")              // = 0xc5d2…a470
//! state_{i+1}  = keccak256(state_i || tx_hash_i)
//! ```
//!
//! The guest replays this rolling hash as part of the `tx_inclusion`
//! statement (see `DESIGN.md` §6.3), so the seed and the update step
//! must match the bootloader's exactly.

use crate::hash::Keccak256Hasher;

/// The initial state of the rolling hash — i.e. `keccak256("")`.
/// Locked in by `hash::tests::keccak256_matches_empty_vector`.
pub const EMPTY_KECCAK: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

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
    /// Fresh hasher, initial state `keccak256("")`.
    pub fn empty() -> Self {
        Self {
            state: EMPTY_KECCAK,
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
    fn empty_hasher_matches_empty_keccak() {
        assert_eq!(TxRollingHasher::empty().current(), EMPTY_KECCAK);
        assert_eq!(EMPTY_KECCAK, keccak256(&[]));
    }

    #[test]
    fn single_push_matches_manual_form() {
        let tx = [0x42u8; 32];
        let mut r = TxRollingHasher::empty();
        r.push(&tx);
        assert_eq!(r.count(), 1);

        // Manually: keccak256(EMPTY_KECCAK || tx)
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&EMPTY_KECCAK);
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

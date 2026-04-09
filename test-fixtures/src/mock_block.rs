//! Block-header and block-window fixtures for the `tx_inclusion`
//! statement.
//!
//! The main job of this module is to build a sequence of synthetic
//! `BlockHeader`s that chain via `parent_hash`, compute the associated
//! block hashes using the bootloader's own `BlockHeader::hash()`
//! implementation, and produce:
//!
//! 1. Our own [`prividium_sd_core::block_header::BlockHeader`] value
//!    whose `hash()` we will call from inside the guest;
//! 2. A 256-entry window of block hashes whose Blake2s concatenation
//!    will form the `last_256_block_hashes_blake` field of the
//!    `ChainStateCommitment`.
//!
//! Because we use the bootloader's `BlockHeader` as the source of truth
//! for each block hash, this also serves as a conformance test for our
//! `core::block_header::hash()` implementation: we assert that the two
//! hashes agree on every synthetic header we build.

use basic_bootloader::bootloader::block_header::BlockHeader as BsBlockHeader;
use prividium_sd_core::block_header::BlockHeader as CoreBlockHeader;
use prividium_sd_core::hash::Blake2sHasher;
use prividium_sd_core::tx_rolling_hash::TxRollingHasher;
use ruint::aliases::B160;
use zk_ee::utils::Bytes32;

/// A single synthetic block, storing both the bootloader's `BlockHeader`
/// (used to compute the ground-truth block hash) and our
/// `prividium-sd-core::block_header::BlockHeader` value.
pub struct MockBlock {
    pub number: u64,
    pub header_bs: BsBlockHeader,
    pub header_core: CoreBlockHeader,
    pub tx_hashes: std::vec::Vec<[u8; 32]>,
    pub block_hash: [u8; 32],
}

impl MockBlock {
    /// Build a block at `block_number` whose body is `tx_hashes`
    /// (ordered), chained to `parent_hash`.
    pub fn new(
        parent_hash: [u8; 32],
        block_number: u64,
        timestamp: u64,
        tx_hashes: std::vec::Vec<[u8; 32]>,
    ) -> Self {
        // Replay the keccak rolling hash to get `transactions_root`.
        let tx_rolling = TxRollingHasher::roll(&tx_hashes);

        // Populate the bootloader's BlockHeader using the same helper
        // the bootloader itself uses (`BlockHeader::new`).
        let beneficiary = B160::ZERO;
        let gas_limit = 30_000_000;
        let gas_used = 0;
        let mix_hash = Bytes32::ZERO;
        let base_fee_per_gas = 1_000_000_000;

        let header_bs = BsBlockHeader::new(
            Bytes32::from_array(parent_hash),
            beneficiary,
            Bytes32::from_array(tx_rolling),
            block_number,
            gas_limit,
            gas_used,
            timestamp,
            mix_hash,
            base_fee_per_gas,
        );

        // Mirror into our own BlockHeader shape, field-for-field.
        let header_core = CoreBlockHeader {
            parent_hash,
            ommers_hash: *header_bs.ommers_hash.as_u8_array_ref(),
            beneficiary: beneficiary.to_be_bytes::<{ B160::BYTES }>(),
            state_root: *header_bs.state_root.as_u8_array_ref(),
            transactions_root: *header_bs.transactions_root.as_u8_array_ref(),
            receipts_root: *header_bs.receipts_root.as_u8_array_ref(),
            logs_bloom: header_bs.logs_bloom,
            difficulty: header_bs.difficulty.to_be_bytes::<32>(),
            number: header_bs.number,
            gas_limit: header_bs.gas_limit,
            gas_used: header_bs.gas_used,
            timestamp: header_bs.timestamp,
            extra_data: header_bs.extra_data.as_slice().to_vec(),
            mix_hash: *header_bs.mix_hash.as_u8_array_ref(),
            nonce: header_bs.nonce,
            base_fee_per_gas: header_bs.base_fee_per_gas,
        };

        let bs_hash = header_bs.hash();
        let core_hash = header_core.hash();
        // Conformance check: the two implementations must agree.
        assert_eq!(
            bs_hash, core_hash,
            "core BlockHeader::hash() diverged from bootloader BlockHeader::hash()",
        );

        Self {
            number: block_number,
            header_bs,
            header_core,
            tx_hashes,
            block_hash: bs_hash,
        }
    }
}

/// Build a sequence of chained blocks with empty transaction lists.
///
/// Block `k` has number `first_number + k`, parent hash equal to the
/// previous block's hash (or [0; 32] for `k == 0`), and the timestamp
/// monotonically incrementing by 1 per block. Used to populate the
/// `last_256_block_hashes_blake` window.
pub fn build_chain(first_number: u64, count: usize) -> std::vec::Vec<MockBlock> {
    let mut blocks = std::vec::Vec::with_capacity(count);
    let mut parent = [0u8; 32];
    for i in 0..count {
        let number = first_number + i as u64;
        let block = MockBlock::new(
            parent,
            number,
            /* timestamp */ 1_700_000_000 + i as u64,
            /* tx_hashes  */ std::vec::Vec::new(),
        );
        parent = block.block_hash;
        blocks.push(block);
    }
    blocks
}

/// A fully-materialized 256-block window.
///
/// `tip_block_number` is the L2 number of the *last* block in the
/// window (i.e. the `chain_state_commitment`'s `block_number`).
/// `blocks` has exactly 256 entries, oldest first.
pub struct BlockWindow {
    pub tip_block_number: u64,
    pub blocks: std::vec::Vec<MockBlock>,
    /// Blake2s of the concatenated 256 block hashes, in the same order
    /// the bootloader would produce them.
    pub last_256_block_hashes_blake: [u8; 32],
}

impl BlockWindow {
    /// Replace the block at window index `i` (i.e. block number
    /// `tip_block_number - 255 + i`) with a block whose body is
    /// `tx_hashes`, keeping the parent-hash chain consistent. This
    /// re-hashes every block from position `i` onward so that
    /// `block_hash[i + 1].parent_hash` equals the new
    /// `block_hash[i]`, and so on.
    pub fn replace_block_txs(&mut self, index: usize, tx_hashes: std::vec::Vec<[u8; 32]>) {
        assert!(index < self.blocks.len());
        // Rewrite blocks[index..] so the chain stays consistent.
        let mut parent = if index == 0 {
            [0u8; 32]
        } else {
            self.blocks[index - 1].block_hash
        };

        // First, swap the tx list at `index` and rebuild that block.
        let old = &self.blocks[index];
        let new = MockBlock::new(parent, old.number, old.header_bs.timestamp, tx_hashes);
        parent = new.block_hash;
        self.blocks[index] = new;

        // Then, rebuild every subsequent block with its old tx list but
        // the updated parent hash.
        for i in (index + 1)..self.blocks.len() {
            let existing = &self.blocks[i];
            let new = MockBlock::new(
                parent,
                existing.number,
                existing.header_bs.timestamp,
                existing.tx_hashes.clone(),
            );
            parent = new.block_hash;
            self.blocks[i] = new;
        }

        self.last_256_block_hashes_blake = compute_window_blake(&self.blocks);
    }

    /// The raw 256-entry window of block hashes in oldest-first order,
    /// ready to be fed into a `TxInclusion` witness.
    pub fn block_hashes(&self) -> std::vec::Vec<[u8; 32]> {
        self.blocks.iter().map(|b| b.block_hash).collect()
    }
}

fn compute_window_blake(blocks: &[MockBlock]) -> [u8; 32] {
    let mut h = Blake2sHasher::new();
    for b in blocks {
        h.update(&b.block_hash);
    }
    h.finalize()
}

/// Build a fresh 256-block window ending at `tip_block_number` with
/// empty-tx blocks. The caller typically follows up with
/// [`BlockWindow::replace_block_txs`] to install a single "interesting"
/// block containing the target tx.
pub fn build_window(tip_block_number: u64) -> BlockWindow {
    let first = tip_block_number - 255;
    let blocks = build_chain(first, 256);
    let last_256_block_hashes_blake = compute_window_blake(&blocks);
    BlockWindow {
        tip_block_number,
        blocks,
        last_256_block_hashes_blake,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_block_hash_matches_bootloader() {
        // The MockBlock::new constructor asserts this already. Just
        // sanity-check that we can build one.
        let tx_hashes = std::vec![[0x11u8; 32], [0x22u8; 32]];
        let block = MockBlock::new([0xaa; 32], 42, 1_700_000_000, tx_hashes.clone());
        assert_eq!(block.number, 42);
        // And that our rolling hash ended up in the transactions_root
        // field (via the bootloader's `BlockHeader::new` constructor).
        assert_eq!(
            *block.header_bs.transactions_root.as_u8_array_ref(),
            TxRollingHasher::roll(&tx_hashes),
        );
    }

    #[test]
    fn chain_parent_hashes_link_up() {
        let chain = build_chain(100, 4);
        assert_eq!(chain.len(), 4);
        assert_eq!(chain[0].header_core.parent_hash, [0u8; 32]);
        for i in 1..chain.len() {
            assert_eq!(chain[i].header_core.parent_hash, chain[i - 1].block_hash);
        }
    }

    #[test]
    fn window_has_256_entries_and_stable_blake() {
        let w = build_window(1000);
        assert_eq!(w.blocks.len(), 256);
        assert_eq!(w.tip_block_number, 1000);
        assert_eq!(w.blocks[0].number, 745);
        assert_eq!(w.blocks[255].number, 1000);

        // Recompute the blake and confirm it matches what the window
        // stored.
        let recomputed = compute_window_blake(&w.blocks);
        assert_eq!(recomputed, w.last_256_block_hashes_blake);
    }

    #[test]
    fn replace_block_txs_keeps_chain_consistent() {
        let mut w = build_window(500);
        let old_last_256 = w.last_256_block_hashes_blake;

        let target_index = 123usize;
        let txs = std::vec![[0x55u8; 32]];
        w.replace_block_txs(target_index, txs.clone());

        // The modified block now has the new tx list.
        assert_eq!(w.blocks[target_index].tx_hashes, txs);

        // Parent chain is still linked.
        for i in 1..w.blocks.len() {
            assert_eq!(w.blocks[i].header_core.parent_hash, w.blocks[i - 1].block_hash);
        }

        // And the window blake changed (we modified an in-window block).
        assert_ne!(old_last_256, w.last_256_block_hashes_blake);
    }
}

//! `tx_inclusion` statement verifier.
//!
//! See `DESIGN.md` §6.3. The witness layout is:
//!
//! ```text
//! public BlockNumber   : u64
//! public TxHash        : [u8; 32]
//! public BatchNumber   : u64
//! public L1Commitment  : [u8; 32]
//!
//! ChainStateCommitment                  // 88 bytes
//! L1VerificationData                    // 160 bytes
//!
//! block_hashes_window  : [[u8;32]; 256]
//! selected_block_index : u32
//!
//! // Full BlockHeader. Every field is fixed-width except
//! // `extra_data`, which is length-prefixed (u32 BE + bytes).
//! block_header         : BlockHeader
//!
//! // Ordered list of tx hashes in the selected block.
//! block_tx_hashes      : u32 BE length + entries * [u8; 32]
//!
//! tx_index             : u32
//! ```

use super::common::{
    read_chain_state_commitment, read_l1_verification_data, write_chain_state_commitment,
    write_l1_verification_data,
};
use super::StatementError;
use crate::block_header::BlockHeader;
use crate::hash::Blake2sHasher;
use crate::params::TxInclusionParams;
use crate::pub_input;
use crate::state_commitment::ChainStateCommitment;
use crate::stored_batch_info::{L1VerificationData, StoredBatchInfo};
use crate::tx_rolling_hash::TxRollingHasher;
use crate::witness::{ByteReader, ByteWriter, WitnessError};
use alloc::vec::Vec;

/// Upper bound on the number of in-block transactions we accept in a
/// single witness. Prevents a malicious witness from coercing the guest
/// into unbounded allocation.
pub const MAX_TXS_PER_BLOCK: usize = 1 << 16;

/// Fully-decoded witness for a `tx_inclusion` statement.
#[derive(Debug, Clone)]
pub struct TxInclusionWitness {
    pub batch_number: u64,
    pub l1_commitment: [u8; 32],
    pub params: TxInclusionParams,

    pub state_commitment: ChainStateCommitment,
    pub l1_verification_data: L1VerificationData,

    pub block_hashes_window: [[u8; 32]; 256],
    pub selected_block_index: u32,

    pub block_header: BlockHeader,
    pub block_tx_hashes: Vec<[u8; 32]>,
    pub tx_index: u32,
}

impl TxInclusionWitness {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ByteWriter::new();
        w.write_u64_be(self.batch_number)
            .write_bytes(&self.l1_commitment)
            .write_u64_be(self.params.block_number)
            .write_bytes(&self.params.tx_hash);

        write_chain_state_commitment(&mut w, &self.state_commitment);
        write_l1_verification_data(&mut w, &self.l1_verification_data);

        for h in &self.block_hashes_window {
            w.write_bytes(h);
        }
        w.write_u32_be(self.selected_block_index);

        write_block_header(&mut w, &self.block_header);

        w.write_u32_be(self.block_tx_hashes.len() as u32);
        for h in &self.block_tx_hashes {
            w.write_bytes(h);
        }

        w.write_u32_be(self.tx_index);
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        let mut r = ByteReader::new(bytes);
        let batch_number = r.read_u64_be()?;
        let l1_commitment = r.read_bytes::<32>()?;
        let block_number = r.read_u64_be()?;
        let tx_hash = r.read_bytes::<32>()?;

        let state_commitment = read_chain_state_commitment(&mut r)?;
        let l1_verification_data = read_l1_verification_data(&mut r)?;

        let mut block_hashes_window = [[0u8; 32]; 256];
        for slot in block_hashes_window.iter_mut() {
            *slot = r.read_bytes::<32>()?;
        }
        let selected_block_index = r.read_u32_be()?;

        let block_header = read_block_header(&mut r)?;

        let n = r.read_u32_be()? as usize;
        if n > MAX_TXS_PER_BLOCK {
            return Err(StatementError::Witness(WitnessError::LengthOverflow));
        }
        let mut block_tx_hashes = Vec::with_capacity(n);
        for _ in 0..n {
            block_tx_hashes.push(r.read_bytes::<32>()?);
        }
        let tx_index = r.read_u32_be()?;
        r.finish()?;

        Ok(Self {
            batch_number,
            l1_commitment,
            params: TxInclusionParams { block_number, tx_hash },
            state_commitment,
            l1_verification_data,
            block_hashes_window,
            selected_block_index,
            block_header,
            block_tx_hashes,
            tx_index,
        })
    }
}

fn write_block_header(w: &mut ByteWriter, h: &BlockHeader) {
    w.write_bytes(&h.parent_hash)
        .write_bytes(&h.ommers_hash)
        .write_bytes(&h.beneficiary)
        .write_bytes(&h.state_root)
        .write_bytes(&h.transactions_root)
        .write_bytes(&h.receipts_root)
        .write_bytes(&h.logs_bloom)
        .write_bytes(&h.difficulty)
        .write_u64_be(h.number)
        .write_u64_be(h.gas_limit)
        .write_u64_be(h.gas_used)
        .write_u64_be(h.timestamp)
        .write_u32_be(h.extra_data.len() as u32)
        .write_bytes(&h.extra_data)
        .write_bytes(&h.mix_hash)
        .write_bytes(&h.nonce)
        .write_u64_be(h.base_fee_per_gas);
}

fn read_block_header(r: &mut ByteReader<'_>) -> Result<BlockHeader, WitnessError> {
    let parent_hash = r.read_bytes::<32>()?;
    let ommers_hash = r.read_bytes::<32>()?;
    let beneficiary = r.read_bytes::<20>()?;
    let state_root = r.read_bytes::<32>()?;
    let transactions_root = r.read_bytes::<32>()?;
    let receipts_root = r.read_bytes::<32>()?;
    let logs_bloom = r.read_bytes::<256>()?;
    let difficulty = r.read_bytes::<32>()?;
    let number = r.read_u64_be()?;
    let gas_limit = r.read_u64_be()?;
    let gas_used = r.read_u64_be()?;
    let timestamp = r.read_u64_be()?;
    let extra_len = r.read_u32_be()? as usize;
    if extra_len > 32 {
        return Err(WitnessError::LengthOverflow);
    }
    let mut extra_data = Vec::with_capacity(extra_len);
    for _ in 0..extra_len {
        extra_data.push(r.read_u8()?);
    }
    let mix_hash = r.read_bytes::<32>()?;
    let nonce = r.read_bytes::<8>()?;
    let base_fee_per_gas = r.read_u64_be()?;

    Ok(BlockHeader {
        parent_hash,
        ommers_hash,
        beneficiary,
        state_root,
        transactions_root,
        receipts_root,
        logs_bloom,
        difficulty,
        number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data,
        mix_hash,
        nonce,
        base_fee_per_gas,
    })
}

pub fn verify(bytes: &[u8]) -> Result<[u8; 32], StatementError> {
    let w = TxInclusionWitness::decode(bytes)?;

    // 1. Bounds on the window index.
    let idx = w.selected_block_index as usize;
    if idx >= 256 {
        return Err(StatementError::BlockWindowMismatch);
    }

    // 2. Window-hash check: the Blake2s of the concatenated 256 block
    //    hashes must equal the state commitment preimage field.
    let mut hasher = Blake2sHasher::new();
    for h in &w.block_hashes_window {
        hasher.update(h);
    }
    let window_blake = hasher.finalize();
    if window_blake != w.state_commitment.last_256_block_hashes_blake {
        return Err(StatementError::WindowHashMismatch);
    }

    // 3. Derive the block number from the batch tip + window index and
    //    match against the public parameter.
    //
    //    Window layout (from the bootloader's
    //    `post_tx_op_proving_singleblock_batch.rs` + `BlockHashes`
    //    ring buffer in `node/bin/src/lib.rs:block_hashes_for_first_block`):
    //
    //    - `window[255]` is the block at height `tip`
    //    - `window[255 - k]` is the block at height `tip - k`, for `k in 0..=min(tip, 255)`
    //    - `window[0 .. 255 - tip]` are zero-padded entries for blocks
    //      that do not exist yet (chain younger than 256 blocks). Any
    //      proof that points into one of those padded slots will be
    //      rejected at step 4 below because `block_header.hash()` will
    //      not match the zero entry.
    //
    //    Computing `derived_block_number` via `tip - (255 - idx)`
    //    rather than the old `(tip - 255) + idx` form avoids
    //    underflow for `tip < 255`.
    let tip = w.state_commitment.block_number;
    let k = 255u64 - idx as u64; // `idx < 256` guaranteed by the bounds check above
    let derived_block_number = tip
        .checked_sub(k)
        .ok_or(StatementError::BlockNumberMismatch)?;
    if derived_block_number != w.params.block_number {
        return Err(StatementError::BlockNumberMismatch);
    }

    // 4. The block header hash must equal the window entry at idx...
    let header_hash = w.block_header.hash();
    if header_hash != w.block_hashes_window[idx] {
        return Err(StatementError::BlockHashMismatch);
    }
    // ...and the header's own `number` field must agree.
    if w.block_header.number != derived_block_number {
        return Err(StatementError::BlockNumberMismatch);
    }

    // 5. Replay the rolling hash over the tx list and cross-check
    //    against the block header's `transactions_root` field.
    let replayed = TxRollingHasher::roll(&w.block_tx_hashes);
    if replayed != w.block_header.transactions_root {
        return Err(StatementError::TxRollingHashMismatch);
    }

    // 6. Bounds-check `tx_index` and confirm the tx at that position
    //    equals the public `tx_hash`.
    let ti = w.tx_index as usize;
    if ti >= w.block_tx_hashes.len() {
        return Err(StatementError::TxIndexMismatch);
    }
    if w.block_tx_hashes[ti] != w.params.tx_hash {
        return Err(StatementError::TxIndexMismatch);
    }

    // 7. Recompute the L1 commitment and match the public one.
    let batch_hash = w.state_commitment.compute();
    let sbi = StoredBatchInfo {
        batch_number: w.batch_number,
        batch_hash,
        l1: w.l1_verification_data,
    };
    if sbi.compute_l1_commitment() != w.l1_commitment {
        return Err(StatementError::L1CommitmentMismatch);
    }

    // 8. Final public-input commitment.
    Ok(pub_input::compute_tx_inclusion(
        w.batch_number,
        &w.l1_commitment,
        &w.params,
    ))
}

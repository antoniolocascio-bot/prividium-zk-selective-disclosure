//! L2 RPC-backed implementation of [`WitnessSource`].
//!
//! Talks to a ZKsync OS JSON-RPC endpoint (typically a Prividium
//! operator's RPC or a local `run_local.sh` node) and builds fully
//! prepared [`ProveRequest`]s for each of the three v0 statements.
//!
//! This module is the ONLY place in the codebase that issues RPC
//! calls and translates JSON responses into the hand-rolled binary
//! witness format from `prividium-sd-core`. The rest of the host
//! pipeline (prover, verifier, bundle) treats the witness bytes as
//! opaque blobs signed by this translation layer.
//!
//! # RPC methods used
//!
//! - `zks_getProof(address, keys, batchNumber)` — Merkle proof for a
//!   single storage slot, anchored to an L1 batch. Used by
//!   `balance_of` and `observable_bytecode_hash`.
//! - `zks_getAccountPreimage(address, batchNumber)` — 124-byte
//!   `AccountProperties::encoding()` blob; added by
//!   <https://github.com/matter-labs/zksync-os-server/pull/1161>.
//!   Also used by `balance_of` and `observable_bytecode_hash`.
//! - `eth_getBlockByNumber(number, full)` — used by `tx_inclusion`
//!   to fetch the 256-block window + the specific target block's
//!   full transaction list.
//!
//! # Trust model
//!
//! The L2 RPC is fully untrusted with respect to the final proof: the
//! guest re-derives the L1 commitment from the raw witness bytes, so
//! a lying RPC can only cause the prover to fail. The L2 is trusted
//! only for data availability — i.e., we expect it to actually
//! return data rather than hang or stall.

use crate::disclosure_request::DisclosureRequest;
use crate::prover::ProveRequest;
use crate::rpc_wire::{
    BatchStorageProof, InnerStorageSlotProof, StateCommitmentPreimage as WireStateCommitment,
    StorageSlotProofEntry,
};
use crate::witness_source::WitnessSource;
use alloy::eips::BlockNumberOrTag;
use alloy::network::{AnyNetwork, AnyRpcBlock, BlockResponse};
use alloy::primitives::{keccak256, Address, Bytes, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use prividium_sd_core::account_properties::{AccountProperties, ENCODED_SIZE as ACCOUNT_PROPS_SIZE};
use prividium_sd_core::block_header::BlockHeader as CoreBlockHeader;
use prividium_sd_core::params::{
    BalanceOfParams, ObservableBytecodeHashParams, TxInclusionParams,
};
use prividium_sd_core::state_commitment::ChainStateCommitment;
use prividium_sd_core::statement_id::StatementId;
use prividium_sd_core::statements::balance_of::BalanceOfWitness;
use prividium_sd_core::statements::observable_bytecode_hash::ObservableBytecodeHashWitness;
use prividium_sd_core::statements::tx_inclusion::TxInclusionWitness;
use prividium_sd_core::stored_batch_info::{L1VerificationData, StoredBatchInfo};
use prividium_sd_core::tree::key::account_properties_slot_key;
use prividium_sd_core::tree::merkle::{
    AccountMerkleProof, FlatStorageLeaf, LeafProof, TREE_DEPTH,
};

/// L2 witness source that hits a live ZKsync OS JSON-RPC endpoint.
///
/// Internally keeps its own tokio runtime so the sync [`prove`]
/// entry point can block on async fetches without pushing async up
/// into the caller.
///
/// [`prove`]: crate::prover::prove
pub struct RpcWitnessSource {
    provider: DynProvider<AnyNetwork>,
    runtime: tokio::runtime::Runtime,
}

/// Errors returned by [`RpcWitnessSource`].
#[derive(Debug, thiserror::Error)]
pub enum RpcWitnessSourceError {
    #[error("failed to build tokio runtime: {0}")]
    Runtime(#[from] std::io::Error),
    #[error("failed to parse L2 RPC URL: {0}")]
    Url(String),
    #[error("L2 RPC transport error: {0}")]
    Rpc(#[from] alloy::transports::TransportError),
    #[error("L2 node returned no proof for batch {batch_number} / address {address:?}")]
    MissingProof {
        batch_number: u64,
        address: Address,
    },
    #[error(
        "L2 node returned no AccountProperties preimage for batch {batch_number} / address {address:?} — \
         account does not exist at this batch (use a non-existence proof instead)"
    )]
    MissingPreimage {
        batch_number: u64,
        address: Address,
    },
    #[error("AccountProperties preimage has wrong length: expected 124, got {0}")]
    PreimageLength(usize),
    #[error("L2 node returned no block for number {0}")]
    MissingBlock(u64),
    #[error("failed to find transaction {tx_hash:?} in any block of the last-256 window for batch {batch_number}")]
    TxNotInWindow {
        batch_number: u64,
        tx_hash: B256,
    },
    #[error("zks_getProof returned {0} proofs, expected exactly 1")]
    UnexpectedProofCount(usize),
    #[error("`eth_getBlockByNumber` response missed required field: {0}")]
    MissingBlockField(&'static str),
}

impl RpcWitnessSource {
    pub fn new(l2_rpc_url: &str) -> Result<Self, RpcWitnessSourceError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let url: url::Url = l2_rpc_url
            .parse()
            .map_err(|e: url::ParseError| RpcWitnessSourceError::Url(e.to_string()))?;
        let provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_http(url)
            .erased();
        Ok(Self { provider, runtime })
    }

    /// Access to the underlying runtime, for callers that want to
    /// drive async code themselves.
    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }

    /// Fetch a `zks_getProof` response for a single storage slot key
    /// under the given account-properties address.
    async fn get_proof(
        &self,
        address: Address,
        batch_number: u64,
    ) -> Result<BatchStorageProof, RpcWitnessSourceError> {
        let keys = vec![address_slot_key(address)];
        let response: Option<BatchStorageProof> = self
            .provider
            .client()
            .request("zks_getProof", (address_properties_addr(), keys, batch_number))
            .await?;
        response.ok_or(RpcWitnessSourceError::MissingProof {
            batch_number,
            address,
        })
    }

    /// Fetch the 124-byte AccountProperties encoding for an account
    /// at a specific batch, via the `zks_getAccountPreimage` method
    /// added in server PR #1161.
    async fn get_account_preimage(
        &self,
        address: Address,
        batch_number: u64,
    ) -> Result<[u8; ACCOUNT_PROPS_SIZE], RpcWitnessSourceError> {
        let response: Option<Bytes> = self
            .provider
            .client()
            .request("zks_getAccountPreimage", (address, batch_number))
            .await?;
        let bytes = response.ok_or(RpcWitnessSourceError::MissingPreimage {
            batch_number,
            address,
        })?;
        if bytes.len() != ACCOUNT_PROPS_SIZE {
            return Err(RpcWitnessSourceError::PreimageLength(bytes.len()));
        }
        let mut out = [0u8; ACCOUNT_PROPS_SIZE];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    async fn build_balance_of_async(
        &self,
        batch_number: u64,
        address: Address,
    ) -> Result<ProveRequest, RpcWitnessSourceError> {
        // 1. Merkle proof for the account-properties slot.
        let proof = self.get_proof(address, batch_number).await?;
        if proof.storage_proofs.len() != 1 {
            return Err(RpcWitnessSourceError::UnexpectedProofCount(
                proof.storage_proofs.len(),
            ));
        }
        let slot_proof = &proof.storage_proofs[0];
        let flat_key = account_properties_slot_key(&address_to_bytes(address));
        let account_proof = translate_proof(&slot_proof.proof, flat_key)?;

        // 2. Preimage (124 bytes) — only used for Existing proofs;
        //    for NonExisting we stuff TRIVIAL_VALUE and claim
        //    balance == 0.
        let (balance, preimage) = match &account_proof {
            AccountMerkleProof::Existing(_) => {
                let p = self.get_account_preimage(address, batch_number).await?;
                let decoded = AccountProperties::decode(&p);
                (decoded.balance, p)
            }
            AccountMerkleProof::NonExisting { .. } => (
                [0u8; 32],
                AccountProperties::TRIVIAL.encode(),
            ),
        };

        // 3. Reconstruct the state commitment + stored batch info so
        //    we can hand the L1 commitment to the prover. The guest
        //    recomputes the same values internally.
        let state_commitment = wire_state_commitment_to_core(
            &proof.state_commitment_preimage,
            account_proof_root(&account_proof),
        );
        let l1_data = wire_l1_to_core(&proof.l1_verification_data);
        let stored_batch = StoredBatchInfo {
            batch_number,
            batch_hash: state_commitment.compute(),
            l1: l1_data,
        };
        let l1_commitment = stored_batch.compute_l1_commitment();

        let params = BalanceOfParams {
            address: address_to_bytes(address),
            balance,
        };
        let witness = BalanceOfWitness {
            batch_number,
            l1_commitment,
            params,
            state_commitment,
            l1_verification_data: l1_data,
            account_proof,
            account_properties_preimage: preimage,
        };

        Ok(ProveRequest {
            statement_id: StatementId::BalanceOf,
            batch_number,
            l1_commitment,
            params_bytes: params.to_bytes().to_vec(),
            witness_bytes: witness.encode(),
        })
    }

    async fn build_observable_bytecode_hash_async(
        &self,
        batch_number: u64,
        address: Address,
    ) -> Result<ProveRequest, RpcWitnessSourceError> {
        let proof = self.get_proof(address, batch_number).await?;
        if proof.storage_proofs.len() != 1 {
            return Err(RpcWitnessSourceError::UnexpectedProofCount(
                proof.storage_proofs.len(),
            ));
        }
        let flat_key = account_properties_slot_key(&address_to_bytes(address));
        let account_proof = translate_proof(&proof.storage_proofs[0].proof, flat_key)?;

        let (obh, preimage) = match &account_proof {
            AccountMerkleProof::Existing(_) => {
                let p = self.get_account_preimage(address, batch_number).await?;
                let decoded = AccountProperties::decode(&p);
                (decoded.observable_bytecode_hash, p)
            }
            AccountMerkleProof::NonExisting { .. } => {
                ([0u8; 32], AccountProperties::TRIVIAL.encode())
            }
        };

        let state_commitment = wire_state_commitment_to_core(
            &proof.state_commitment_preimage,
            account_proof_root(&account_proof),
        );
        let l1_data = wire_l1_to_core(&proof.l1_verification_data);
        let stored_batch = StoredBatchInfo {
            batch_number,
            batch_hash: state_commitment.compute(),
            l1: l1_data,
        };
        let l1_commitment = stored_batch.compute_l1_commitment();

        let params = ObservableBytecodeHashParams {
            address: address_to_bytes(address),
            observable_bytecode_hash: obh,
        };
        let witness = ObservableBytecodeHashWitness {
            batch_number,
            l1_commitment,
            params,
            state_commitment,
            l1_verification_data: l1_data,
            account_proof,
            account_properties_preimage: preimage,
        };

        Ok(ProveRequest {
            statement_id: StatementId::ObservableBytecodeHash,
            batch_number,
            l1_commitment,
            params_bytes: params.to_bytes().to_vec(),
            witness_bytes: witness.encode(),
        })
    }

    async fn build_tx_inclusion_async(
        &self,
        batch_number: u64,
        tx_hash: B256,
    ) -> Result<ProveRequest, RpcWitnessSourceError> {
        // 1. Anchor via zks_getProof with an arbitrary address/key
        //    (we only care about the state_commitment_preimage +
        //    l1_verification_data, not the Merkle proof itself). We
        //    reuse the account-properties address with an all-zero
        //    key as the cheapest possible proof request.
        let anchor = self
            .get_proof(address_properties_addr(), batch_number)
            .await?;
        // Flat key for the anchor proof. We asked for a slot under
        // `ACCOUNT_PROPERTIES_STORAGE_ADDRESS` keyed by the all-zero
        // user address — which is essentially never touched, so the
        // server returns a `NonExisting` bracketing proof. Either
        // way, the root it recomputes IS the tree root for the batch.
        let anchor_flat_key = account_properties_slot_key(&[0u8; 20]);
        let state_cm = wire_state_commitment_to_core(
            &anchor.state_commitment_preimage,
            anchor
                .storage_proofs
                .first()
                .map(|sp| implied_root(&sp.proof, anchor_flat_key))
                .unwrap_or([0u8; 32]),
        );
        let l1_data = wire_l1_to_core(&anchor.l1_verification_data);

        // 2. Fetch the 256-block window ending at `state_cm.block_number`.
        //
        // Window layout mirrors the server's
        // `block_hashes_for_first_block` + subsequent sliding-window
        // updates:
        //
        //     window[255]       = block `tip`
        //     window[255 - k]   = block `tip - k`, for k in 0..=min(tip, 255)
        //     window[0 .. 255 - tip] = padding (all zeros) when the
        //         chain has fewer than 256 blocks yet
        //
        // The guest's verifier hashes the whole 256-entry window with
        // blake2s and compares against the state commitment preimage,
        // so the padding must be literal zeros — **not** duplicates
        // of the genesis block hash.
        let tip = state_cm.block_number;
        let valid_entries = ((tip + 1).min(256)) as usize;
        let first_valid_idx = 256 - valid_entries;

        let mut window_hashes = [[0u8; 32]; 256];
        let mut selected: Option<(usize, CoreBlockHeader, Vec<[u8; 32]>, usize)> = None;

        for (i, slot) in window_hashes
            .iter_mut()
            .enumerate()
            .skip(first_valid_idx)
        {
            // For i in [first_valid_idx .. 255], block number =
            // tip - (255 - i). When tip < 255 this still works
            // because i >= 255 - tip by construction.
            let block_number = tip - (255 - i as u64);
            let block = self
                .provider
                .get_block_by_number(BlockNumberOrTag::Number(block_number))
                .full()
                .await?
                .ok_or(RpcWitnessSourceError::MissingBlock(block_number))?;

            // Compute each block's hash with our in-tree RLP + Keccak
            // path (same one the guest uses), not the one the RPC
            // reported. If the RPC is lying, the guest's window-blake
            // check will catch it.
            let (core_header, tx_hashes) = block_to_core_header(&block)?;
            *slot = core_header.hash();

            if selected.is_none() {
                if let Some(idx) = tx_hashes.iter().position(|t| t == tx_hash.as_slice()) {
                    selected = Some((i, core_header, tx_hashes, idx));
                }
            }
        }

        let (window_index, block_header, block_tx_hashes, tx_index) =
            selected.ok_or(RpcWitnessSourceError::TxNotInWindow {
                batch_number,
                tx_hash,
            })?;

        // 3. Build the final witness + compute the L1 commitment.
        let stored_batch = StoredBatchInfo {
            batch_number,
            batch_hash: state_cm.compute(),
            l1: l1_data,
        };
        let l1_commitment = stored_batch.compute_l1_commitment();

        // Same `tip - (255 - idx)` form the guest uses; avoids
        // underflow for early chain.
        let derived_block_number = tip - (255 - window_index as u64);
        let params = TxInclusionParams {
            block_number: derived_block_number,
            tx_hash: tx_hash.0,
        };

        let witness = TxInclusionWitness {
            batch_number,
            l1_commitment,
            params,
            state_commitment: state_cm,
            l1_verification_data: l1_data,
            block_hashes_window: window_hashes,
            selected_block_index: window_index as u32,
            block_header,
            block_tx_hashes,
            tx_index: tx_index as u32,
        };

        Ok(ProveRequest {
            statement_id: StatementId::TxInclusion,
            batch_number,
            l1_commitment,
            params_bytes: params.to_bytes().to_vec(),
            witness_bytes: witness.encode(),
        })
    }
}

impl WitnessSource for RpcWitnessSource {
    type Error = RpcWitnessSourceError;

    async fn fetch(&self, request: DisclosureRequest) -> Result<ProveRequest, Self::Error> {
        match request {
            DisclosureRequest::BalanceOf {
                batch_number,
                address,
            } => self.build_balance_of_async(batch_number, address).await,
            DisclosureRequest::ObservableBytecodeHash {
                batch_number,
                address,
            } => {
                self.build_observable_bytecode_hash_async(batch_number, address)
                    .await
            }
            DisclosureRequest::TxInclusion {
                batch_number,
                tx_hash,
            } => self.build_tx_inclusion_async(batch_number, tx_hash).await,
        }
    }
}

// ======== helpers ========

/// The synthetic address `0x8003` under which ZKsync OS stores
/// account-properties hashes. See
/// `prividium_sd_core::tree::key::ACCOUNT_PROPERTIES_STORAGE_ADDRESS_PADDED`
/// for the padded form; here we need the raw 20-byte `Address`.
fn address_properties_addr() -> Address {
    let mut bytes = [0u8; 20];
    bytes[18] = 0x80;
    bytes[19] = 0x03;
    Address::from(bytes)
}

/// Given a user address, return the 32-byte storage key under
/// `ACCOUNT_PROPERTIES_STORAGE_ADDRESS` at which the account's
/// properties hash lives. This matches
/// `basic_system::flat_storage_model::address_into_special_storage_key`.
fn address_slot_key(user_address: Address) -> B256 {
    let mut key = [0u8; 32];
    key[12..].copy_from_slice(user_address.as_slice());
    B256::from(key)
}

fn address_to_bytes(address: Address) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(address.as_slice());
    out
}

/// Translate a wire [`InnerStorageSlotProof`] into our core
/// [`AccountMerkleProof`], padding Merkle paths to the full 64-entry
/// uncompressed form that the guest's verifier expects.
///
/// `flat_key` must be the flat storage key the proof is *for* — i.e.
/// `blake2s(address_padded_32_be || storage_key_32)`. For the
/// `Existing` variant the server does not return the leaf key on the
/// wire (the outer `StorageSlotProof.key` carries the address-scoped
/// key, not the flat-derived one), so the caller must compute and
/// supply it. For the `NonExisting` variant each neighbour carries
/// its own `leafKey` field on the wire, and `flat_key` is ignored.
fn translate_proof(
    wire: &InnerStorageSlotProof,
    flat_key: [u8; 32],
) -> Result<AccountMerkleProof, RpcWitnessSourceError> {
    match wire {
        InnerStorageSlotProof::Existing(entry) => {
            let proof = existing_entry_to_leaf_proof(entry, flat_key)?;
            Ok(AccountMerkleProof::Existing(proof))
        }
        InnerStorageSlotProof::NonExisting {
            left_neighbor,
            right_neighbor,
        } => {
            let left = existing_entry_to_leaf_proof(
                &left_neighbor.inner,
                left_neighbor.leaf_key.0,
            )?;
            let right = existing_entry_to_leaf_proof(
                &right_neighbor.inner,
                right_neighbor.leaf_key.0,
            )?;
            Ok(AccountMerkleProof::NonExisting { left, right })
        }
    }
}

/// Convert a wire `StorageSlotProofEntry` into a core `LeafProof`,
/// padding `siblings` to a full 64-entry path with empty-subtree
/// hashes so the guest's uncompressed-path verifier accepts it.
fn existing_entry_to_leaf_proof(
    entry: &StorageSlotProofEntry,
    leaf_key: [u8; 32],
) -> Result<LeafProof, RpcWitnessSourceError> {
    use prividium_sd_core::hash::Blake2sHasher;

    // Precompute empty-subtree hashes up to TREE_DEPTH - 1. Level 0
    // is the empty-leaf hash; level i is `blake2s(level_{i-1} ||
    // level_{i-1})`.
    let empty_leaf = FlatStorageLeaf::EMPTY.hash();
    let mut empty_hashes = [[0u8; 32]; TREE_DEPTH];
    empty_hashes[0] = empty_leaf;
    for i in 1..TREE_DEPTH {
        let mut h = Blake2sHasher::new();
        h.update(&empty_hashes[i - 1]);
        h.update(&empty_hashes[i - 1]);
        empty_hashes[i] = h.finalize();
    }

    let mut path = Box::new([[0u8; 32]; TREE_DEPTH]);
    for i in 0..TREE_DEPTH {
        path[i] = entry
            .siblings
            .get(i)
            .map(|s| s.0)
            .unwrap_or(empty_hashes[i]);
    }

    Ok(LeafProof {
        index: entry.index,
        leaf: FlatStorageLeaf {
            key: leaf_key,
            value: entry.value.0,
            next: entry.next_index,
        },
        path,
    })
}

/// Recover the tree root implied by an `InnerStorageSlotProof`,
/// given the flat key that the outer proof is for.
///
/// `flat_key` is only relevant for the `Existing` variant — the
/// `NonExisting` case reads the real leaf keys off the neighbours.
/// This helper is used by the tx_inclusion anchor path, where we
/// deliberately request a proof for a key we know is absent so we
/// always hit the `NonExisting` branch and get the tree root
/// via the bracketing neighbours.
fn implied_root(inner: &InnerStorageSlotProof, flat_key: [u8; 32]) -> [u8; 32] {
    match inner {
        InnerStorageSlotProof::Existing(entry) => {
            if let Ok(lp) = existing_entry_to_leaf_proof(entry, flat_key) {
                lp.recompute_root()
            } else {
                [0u8; 32]
            }
        }
        InnerStorageSlotProof::NonExisting { left_neighbor, .. } => {
            if let Ok(lp) =
                existing_entry_to_leaf_proof(&left_neighbor.inner, left_neighbor.leaf_key.0)
            {
                lp.recompute_root()
            } else {
                [0u8; 32]
            }
        }
    }
}

fn account_proof_root(proof: &AccountMerkleProof) -> [u8; 32] {
    match proof {
        AccountMerkleProof::Existing(lp) => lp.recompute_root(),
        AccountMerkleProof::NonExisting { left, .. } => left.recompute_root(),
    }
}

fn wire_state_commitment_to_core(
    wire: &WireStateCommitment,
    state_root: [u8; 32],
) -> ChainStateCommitment {
    ChainStateCommitment {
        state_root,
        next_free_slot: wire.next_free_slot.to::<u64>(),
        block_number: wire.block_number.to::<u64>(),
        last_256_block_hashes_blake: wire.last_256_block_hashes_blake.0,
        last_block_timestamp: wire.last_block_timestamp.to::<u64>(),
    }
}

fn wire_l1_to_core(wire: &crate::rpc_wire::L1VerificationData) -> L1VerificationData {
    let mut number_of_layer1_txs = [0u8; 32];
    number_of_layer1_txs[24..].copy_from_slice(&wire.number_of_layer1_txs.to_be_bytes());
    L1VerificationData {
        number_of_layer1_txs,
        priority_operations_hash: wire.priority_operations_hash.0,
        dependency_roots_rolling_hash: wire.dependency_roots_rolling_hash.0,
        l2_logs_tree_root: wire.l2_to_l1_logs_root_hash.0,
        commitment: wire.commitment.0,
    }
}

/// Convert an `eth_getBlockByNumber(full=true)` response into our
/// `CoreBlockHeader` + ordered tx hashes.
///
/// We always call the RPC with `full = true` so the block body
/// carries the transactions themselves (not just hashes), then
/// extract each transaction's hash via alloy's `TransactionResponse`
/// trait which is implemented by the RPC-level `Transaction<T>`
/// wrapper for any envelope type.
fn block_to_core_header(
    block: &AnyRpcBlock,
) -> Result<(CoreBlockHeader, Vec<[u8; 32]>), RpcWitnessSourceError> {
    use alloy::network::primitives::BlockTransactions;
    use alloy::network::TransactionResponse;

    let header = block.header();
    let header_inner = &header.inner;

    let beneficiary: [u8; 20] = header_inner.beneficiary.into_array();
    let difficulty_bytes: [u8; 32] = header_inner.difficulty.to_be_bytes();

    // `nonce` and `mix_hash` are `Option<FixedBytes<_>>` on the
    // consensus `Header` because they can be absent for post-merge
    // blocks on some networks. ZKsync OS blocks set them both to
    // zero, so falling back to a zeroed default is correct.
    let nonce_bytes: [u8; 8] = header_inner
        .nonce
        .map(|n| n.0)
        .unwrap_or_default();
    let mix_hash_bytes: [u8; 32] = header_inner
        .mix_hash
        .map(|m| m.0)
        .unwrap_or_default();

    // `logs_bloom` must be zeroed out when computing the block
    // hash. The ZKsync OS sequencer stores the actual (non-zero)
    // bloom filter in the block repository, but the bootloader's
    // `BlockHeader::hash()` — and therefore the hash that ends up in
    // `last_256_block_hashes_blake` and ultimately the L1 state
    // commitment — is computed over a zeroed bloom. See the comment
    // in the server's `zks_impl.rs` (get_proof_impl):
    //
    //     // `logs_bloom` must be zeroed out when computing block
    //     // hashes due to how block hashes are defined elsewhere
    //     // in the codebase.
    //
    // `eth_getBlockByNumber` returns the REAL bloom, so we discard
    // it here and substitute the canonical zero value that the
    // server's hash path uses. Pulled out as a separate binding (not
    // read from `header_inner.logs_bloom`) to make this intentional.
    let _actual_bloom_ignored = header_inner.logs_bloom;
    let logs_bloom_bytes: [u8; 256] = [0u8; 256];

    // Extract the ordered list of tx hashes from the block body. We
    // request `full = true` so we always see `Transactions::Full`;
    // fall through on `Hashes` for robustness but error on `Uncle`.
    let transactions = block.transactions();
    let tx_hashes: Vec<[u8; 32]> = match transactions {
        BlockTransactions::Full(txs) => txs.iter().map(|t| t.tx_hash().0).collect(),
        BlockTransactions::Hashes(hs) => hs.iter().map(|h| h.0).collect(),
        BlockTransactions::Uncle => {
            return Err(RpcWitnessSourceError::MissingBlockField("transactions"))
        }
    };

    let core = CoreBlockHeader {
        parent_hash: header_inner.parent_hash.0,
        ommers_hash: header_inner.ommers_hash.0,
        beneficiary,
        state_root: header_inner.state_root.0,
        transactions_root: header_inner.transactions_root.0,
        receipts_root: header_inner.receipts_root.0,
        logs_bloom: logs_bloom_bytes,
        difficulty: difficulty_bytes,
        number: header_inner.number,
        gas_limit: header_inner.gas_limit,
        gas_used: header_inner.gas_used,
        timestamp: header_inner.timestamp,
        extra_data: header_inner.extra_data.to_vec(),
        mix_hash: mix_hash_bytes,
        nonce: nonce_bytes,
        base_fee_per_gas: header_inner.base_fee_per_gas.unwrap_or_default(),
    };

    Ok((core, tx_hashes))
}

// Silence unused warning for `keccak256` if nothing in this file
// needs it in a later revision.
#[allow(dead_code)]
fn _keccak_importer(input: &[u8]) -> [u8; 32] {
    keccak256(input).0
}

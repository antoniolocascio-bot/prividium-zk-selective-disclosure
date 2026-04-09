//! End-to-end scenarios: build a valid witness for each statement,
//! entirely in memory, and return the expected public-input commitment.
//!
//! These are the fixtures the statement-verifier unit tests in `core`
//! use (via a dev-dependency) and that the airbender integration tests
//! will feed to the guest in Phase 4.

use crate::mock_block::build_window;
use crate::MockStateTree;
use prividium_sd_core::account_properties::AccountProperties;
use prividium_sd_core::params::{
    BalanceOfParams, ObservableBytecodeHashParams, TxInclusionParams,
};
use prividium_sd_core::pub_input;
use prividium_sd_core::state_commitment::ChainStateCommitment;
use prividium_sd_core::statements::balance_of::BalanceOfWitness;
use prividium_sd_core::statements::observable_bytecode_hash::ObservableBytecodeHashWitness;
use prividium_sd_core::statements::tx_inclusion::TxInclusionWitness;
use prividium_sd_core::statement_id::StatementId;
use prividium_sd_core::stored_batch_info::{L1VerificationData, StoredBatchInfo};

/// A fully-materialized scenario: everything a host-side test needs to
/// push a proof through the guest and verify its public output.
pub struct Scenario {
    pub statement_id: StatementId,
    pub batch_number: u64,
    pub l1_commitment: [u8; 32],
    pub witness_bytes: std::vec::Vec<u8>,
    pub expected_pub_input: [u8; 32],
}

/// Canned, non-zero L1VerificationData used by every scenario. Keeping
/// it constant makes reasoning about expected commitments simpler and
/// gives tests a single place to tweak.
fn sample_l1_verification_data() -> L1VerificationData {
    L1VerificationData {
        number_of_layer1_txs: {
            let mut b = [0u8; 32];
            b[31] = 3;
            b
        },
        priority_operations_hash: [0x11; 32],
        dependency_roots_rolling_hash: [0x22; 32],
        l2_logs_tree_root: [0x33; 32],
        commitment: [0x44; 32],
    }
}

/// Derive the L1 commitment from a state tree + preimage fields.
fn stored_batch_and_commitment(
    batch_number: u64,
    state_commitment: &ChainStateCommitment,
    l1: &L1VerificationData,
) -> (StoredBatchInfo, [u8; 32]) {
    let batch_hash = state_commitment.compute();
    let sbi = StoredBatchInfo {
        batch_number,
        batch_hash,
        l1: l1.clone(),
    };
    let l1_commitment = sbi.compute_l1_commitment();
    (sbi, l1_commitment)
}

/// Build a `balance_of` scenario for an account that already exists in
/// the tree. Also inserts a handful of "neighbour" accounts to make the
/// tree non-trivial.
pub fn balance_of_scenario(
    batch_number: u64,
    block_number: u64,
    user_address: [u8; 20],
    balance_low64: u64,
) -> Scenario {
    let mut tree = MockStateTree::new();
    // Populate some neighbouring accounts so the proof is not trivially
    // adjacent to a sentinel.
    tree.insert_account([0x01; 20], &make_account(1));
    tree.insert_account([0xfe; 20], &make_account(2));

    let mut props = AccountProperties::TRIVIAL;
    props.balance = u256_from_u64(balance_low64);
    props.nonce = 5;
    tree.insert_account(user_address, &props);

    let state_commitment = ChainStateCommitment {
        state_root: tree.root(),
        next_free_slot: tree.next_free_slot(),
        block_number,
        // Not bound in this statement, but still mixed into the state
        // commitment blake. Any 32-byte value works.
        last_256_block_hashes_blake: [0u8; 32],
        last_block_timestamp: 1_700_000_000,
    };
    let l1 = sample_l1_verification_data();
    let (_sbi, l1_commitment) =
        stored_batch_and_commitment(batch_number, &state_commitment, &l1);

    let params = BalanceOfParams {
        address: user_address,
        balance: props.balance,
    };
    let witness = BalanceOfWitness {
        batch_number,
        l1_commitment,
        params,
        state_commitment,
        l1_verification_data: l1,
        account_proof: tree.get_account_proof(user_address),
        account_properties_preimage: props.encode(),
    };

    let expected_pub_input =
        pub_input::compute_balance_of(batch_number, &l1_commitment, &params);

    Scenario {
        statement_id: StatementId::BalanceOf,
        batch_number,
        l1_commitment,
        witness_bytes: witness.encode(),
        expected_pub_input,
    }
}

/// Build a `balance_of` scenario for an address that has never been
/// written. The public balance must be zero; otherwise the guest will
/// reject it.
pub fn balance_of_non_existing_scenario(
    batch_number: u64,
    block_number: u64,
    absent_address: [u8; 20],
) -> Scenario {
    let mut tree = MockStateTree::new();
    tree.insert_account([0x01; 20], &make_account(1));
    tree.insert_account([0xfe; 20], &make_account(2));

    let state_commitment = ChainStateCommitment {
        state_root: tree.root(),
        next_free_slot: tree.next_free_slot(),
        block_number,
        last_256_block_hashes_blake: [0u8; 32],
        last_block_timestamp: 1_700_000_000,
    };
    let l1 = sample_l1_verification_data();
    let (_sbi, l1_commitment) =
        stored_batch_and_commitment(batch_number, &state_commitment, &l1);

    let params = BalanceOfParams {
        address: absent_address,
        balance: [0u8; 32],
    };
    // The preimage for a non-existing account is not inspected by the
    // verifier, but we still have to supply *some* 124 bytes.
    let props = AccountProperties::TRIVIAL;
    let witness = BalanceOfWitness {
        batch_number,
        l1_commitment,
        params,
        state_commitment,
        l1_verification_data: l1,
        account_proof: tree.get_account_proof(absent_address),
        account_properties_preimage: props.encode(),
    };

    let expected_pub_input =
        pub_input::compute_balance_of(batch_number, &l1_commitment, &params);

    Scenario {
        statement_id: StatementId::BalanceOf,
        batch_number,
        l1_commitment,
        witness_bytes: witness.encode(),
        expected_pub_input,
    }
}

/// Build an `observable_bytecode_hash` scenario for an existing account.
pub fn observable_bytecode_hash_scenario(
    batch_number: u64,
    block_number: u64,
    user_address: [u8; 20],
    observable_hash: [u8; 32],
) -> Scenario {
    let mut tree = MockStateTree::new();
    tree.insert_account([0x01; 20], &make_account(1));
    tree.insert_account([0xfe; 20], &make_account(2));

    let mut props = AccountProperties::TRIVIAL;
    props.observable_bytecode_hash = observable_hash;
    props.observable_bytecode_len = 42;
    props.bytecode_hash = [0xcc; 32];
    props.unpadded_code_len = 42;
    tree.insert_account(user_address, &props);

    let state_commitment = ChainStateCommitment {
        state_root: tree.root(),
        next_free_slot: tree.next_free_slot(),
        block_number,
        last_256_block_hashes_blake: [0u8; 32],
        last_block_timestamp: 1_700_000_000,
    };
    let l1 = sample_l1_verification_data();
    let (_sbi, l1_commitment) =
        stored_batch_and_commitment(batch_number, &state_commitment, &l1);

    let params = ObservableBytecodeHashParams {
        address: user_address,
        observable_bytecode_hash: observable_hash,
    };
    let witness = ObservableBytecodeHashWitness {
        batch_number,
        l1_commitment,
        params,
        state_commitment,
        l1_verification_data: l1,
        account_proof: tree.get_account_proof(user_address),
        account_properties_preimage: props.encode(),
    };

    let expected_pub_input =
        pub_input::compute_observable_bytecode_hash(batch_number, &l1_commitment, &params);

    Scenario {
        statement_id: StatementId::ObservableBytecodeHash,
        batch_number,
        l1_commitment,
        witness_bytes: witness.encode(),
        expected_pub_input,
    }
}

/// Build a `tx_inclusion` scenario. The target block sits at the tip of
/// the window (window index 255, = `tip_block_number`) and contains
/// `tx_hashes` in order; `tx_index` selects which tx hash becomes the
/// public parameter.
pub fn tx_inclusion_scenario(
    batch_number: u64,
    tip_block_number: u64,
    target_window_index: u32,
    tx_hashes: std::vec::Vec<[u8; 32]>,
    tx_index: u32,
) -> Scenario {
    assert!((target_window_index as usize) < 256);
    assert!((tx_index as usize) < tx_hashes.len());

    let mut window = build_window(tip_block_number);
    window.replace_block_txs(target_window_index as usize, tx_hashes.clone());

    // Build a trivial state tree just so we have a well-defined
    // `state_root` to bind into the state commitment. The tree's
    // contents do not matter for tx_inclusion.
    let tree = MockStateTree::new();

    let state_commitment = ChainStateCommitment {
        state_root: tree.root(),
        next_free_slot: tree.next_free_slot(),
        block_number: tip_block_number,
        last_256_block_hashes_blake: window.last_256_block_hashes_blake,
        last_block_timestamp: 1_700_000_000 + 255,
    };
    let l1 = sample_l1_verification_data();
    let (_sbi, l1_commitment) =
        stored_batch_and_commitment(batch_number, &state_commitment, &l1);

    let selected_block = &window.blocks[target_window_index as usize];
    let public_block_number = selected_block.number;
    let public_tx_hash = tx_hashes[tx_index as usize];
    let params = TxInclusionParams {
        block_number: public_block_number,
        tx_hash: public_tx_hash,
    };

    let mut window_array = [[0u8; 32]; 256];
    for (i, b) in window.blocks.iter().enumerate() {
        window_array[i] = b.block_hash;
    }

    let witness = TxInclusionWitness {
        batch_number,
        l1_commitment,
        params,
        state_commitment,
        l1_verification_data: l1,
        block_hashes_window: window_array,
        selected_block_index: target_window_index,
        block_header: selected_block.header_core.clone(),
        block_tx_hashes: tx_hashes,
        tx_index,
    };

    let expected_pub_input =
        pub_input::compute_tx_inclusion(batch_number, &l1_commitment, &params);

    Scenario {
        statement_id: StatementId::TxInclusion,
        batch_number,
        l1_commitment,
        witness_bytes: witness.encode(),
        expected_pub_input,
    }
}

fn make_account(balance_low64: u64) -> AccountProperties {
    let mut a = AccountProperties::TRIVIAL;
    a.balance = u256_from_u64(balance_low64);
    a.nonce = 1;
    a
}

fn u256_from_u64(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    b
}

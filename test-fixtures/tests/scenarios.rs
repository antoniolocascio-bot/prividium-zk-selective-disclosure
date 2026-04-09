//! End-to-end scenario tests: build a scenario, run it through the
//! core statement verifier, and confirm the resulting public input
//! matches the scenario's expected value. Also exercise a handful of
//! tamper cases that must be rejected.
//!
//! This file is where Phase 3 actually ties the knot: if these tests
//! pass, the statement verifiers in `prividium-sd-core::statements`
//! accept valid witnesses produced against the real `TestingTree` /
//! real bootloader `BlockHeader::hash` and correctly compute the
//! public-input commitment that the guest will commit in Phase 4.

use prividium_sd_core::statements::{self, StatementError};
use prividium_sd_test_fixtures::scenarios;

const BATCH_NUMBER: u64 = 42;
const BLOCK_NUMBER: u64 = 1234;

#[test]
fn balance_of_existing_account_round_trip() {
    let addr = [0xabu8; 20];
    let balance: u64 = 0xdead_beef;
    let s = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, balance);

    let pub_input = statements::verify(s.statement_id, &s.witness_bytes)
        .expect("scenario witness must verify");
    assert_eq!(pub_input, s.expected_pub_input);
}

#[test]
fn balance_of_non_existing_account_round_trip() {
    let absent = [0x77u8; 20];
    let s = scenarios::balance_of_non_existing_scenario(BATCH_NUMBER, BLOCK_NUMBER, absent);

    let pub_input = statements::verify(s.statement_id, &s.witness_bytes)
        .expect("non-existing scenario must verify");
    assert_eq!(pub_input, s.expected_pub_input);
}

#[test]
fn observable_bytecode_hash_round_trip() {
    let addr = [0xcdu8; 20];
    let hash = [0xbeu8; 32];
    let s = scenarios::observable_bytecode_hash_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, hash);

    let pub_input = statements::verify(s.statement_id, &s.witness_bytes)
        .expect("observable bytecode hash scenario must verify");
    assert_eq!(pub_input, s.expected_pub_input);
}

#[test]
fn tx_inclusion_round_trip() {
    let tip: u64 = 2_000;
    let target_index: u32 = 100; // a block in the middle of the window
    let tx_hashes = vec![
        [0x01u8; 32],
        [0x02u8; 32],
        [0x03u8; 32],
        [0x04u8; 32],
    ];
    let tx_index: u32 = 2;
    let s = scenarios::tx_inclusion_scenario(
        BATCH_NUMBER,
        tip,
        target_index,
        tx_hashes.clone(),
        tx_index,
    );

    let pub_input = statements::verify(s.statement_id, &s.witness_bytes)
        .expect("tx inclusion scenario must verify");
    assert_eq!(pub_input, s.expected_pub_input);

    // The public input encodes both the claimed block number and the
    // tx hash, so we can cross-check via the core helper.
    let expected_block_number = tip - 255 + target_index as u64;
    let expected = prividium_sd_core::pub_input::compute_tx_inclusion(
        s.batch_number,
        &s.l1_commitment,
        &prividium_sd_core::params::TxInclusionParams {
            block_number: expected_block_number,
            tx_hash: tx_hashes[tx_index as usize],
        },
    );
    assert_eq!(pub_input, expected);
}

/// Flipping one bit of the balance in the public parameter must make
/// the proof fail — either as a `PublicParamMismatch` (if the hash
/// check runs first) or an `AccountPropertiesHashMismatch` (if Merkle
/// runs first). Both are valid; we accept either.
#[test]
fn balance_of_tampered_balance_is_rejected() {
    let addr = [0xabu8; 20];
    let s = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, 100);
    let mut bytes = s.witness_bytes.clone();

    // Public BalanceOfParams.balance lives at offset:
    //   8  (batch_number)
    // + 32 (l1_commitment)
    // + 20 (address)
    // = 60, and is 32 bytes.
    bytes[60 + 31] ^= 0x01;

    let err = statements::verify(s.statement_id, &bytes).unwrap_err();
    assert!(matches!(
        err,
        StatementError::PublicParamMismatch | StatementError::AccountPropertiesHashMismatch
    ));
}

#[test]
fn balance_of_tampered_l1_commitment_is_rejected() {
    let addr = [0xabu8; 20];
    let s = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, 100);
    let mut bytes = s.witness_bytes.clone();

    // l1_commitment lives at offset 8 (after batch_number), 32 bytes.
    bytes[8 + 0] ^= 0xff;

    let err = statements::verify(s.statement_id, &bytes).unwrap_err();
    assert_eq!(err, StatementError::L1CommitmentMismatch);
}

#[test]
fn balance_of_non_existing_with_nonzero_claim_is_rejected() {
    // Start from the existing-account scenario, keep the proof the
    // same but mutate it to look non-existing: there is no cheap way
    // to swap the proof variant from the outside, so instead we
    // hand-build a non-existing scenario and then tamper the claimed
    // balance to non-zero.
    let absent = [0x77u8; 20];
    let s = scenarios::balance_of_non_existing_scenario(BATCH_NUMBER, BLOCK_NUMBER, absent);
    let mut bytes = s.witness_bytes.clone();

    // Overwrite the last byte of the public balance with 1.
    bytes[60 + 31] = 1;

    let err = statements::verify(s.statement_id, &bytes).unwrap_err();
    assert_eq!(err, StatementError::NonExistingAccountClaim);
}

#[test]
fn tx_inclusion_wrong_tx_hash_is_rejected() {
    let tip: u64 = 2_000;
    let tx_hashes = vec![[0x10u8; 32], [0x20u8; 32]];
    let s = scenarios::tx_inclusion_scenario(BATCH_NUMBER, tip, 10, tx_hashes, 0);

    let mut bytes = s.witness_bytes.clone();
    // Public tx_hash lives at offset 8 + 32 + 8 = 48 and is 32 bytes.
    bytes[48 + 0] ^= 0x01;

    let err = statements::verify(s.statement_id, &bytes).unwrap_err();
    assert_eq!(err, StatementError::TxIndexMismatch);
}

#[test]
fn tx_inclusion_wrong_block_number_is_rejected() {
    let tip: u64 = 2_000;
    let tx_hashes = vec![[0x10u8; 32], [0x20u8; 32]];
    let s = scenarios::tx_inclusion_scenario(BATCH_NUMBER, tip, 10, tx_hashes, 0);

    let mut bytes = s.witness_bytes.clone();
    // Public block_number lives at offset 8 + 32 = 40 and is 8 bytes (BE).
    // Bump it to something obviously wrong.
    bytes[40 + 7] ^= 0xff;

    let err = statements::verify(s.statement_id, &bytes).unwrap_err();
    assert_eq!(err, StatementError::BlockNumberMismatch);
}

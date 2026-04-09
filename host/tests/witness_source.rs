//! Integration tests for the `WitnessSource` → `prove_from_source`
//! → `verify_bundle` pipeline, using the in-memory
//! `MockWitnessSource`.
//!
//! These tests exercise the same code paths as the existing
//! `end_to_end.rs` tests, but via the higher-level
//! `DisclosureRequest` surface that the CLI will use. A passing test
//! here means:
//!
//! 1. `DisclosureRequest → WitnessSource::fetch → ProveRequest`
//!    round-trips correctly through the trait boundary.
//! 2. `prove_from_source` correctly blocks on async witness fetches
//!    and then drives the airbender prover.
//! 3. The resulting bundle verifies end-to-end via the existing
//!    `verify_bundle` path.

use alloy::primitives::Address;
use prividium_sd_core::statement_id::StatementId;
use prividium_sd_host::witness_source::mock::MockWitnessSource;
use prividium_sd_host::{
    prove_from_source, verify_bundle, DisclosureRequest, MockL1Source, ProveRequest,
    VerifiedDisclosure,
};
use prividium_sd_test_fixtures::scenarios;
use std::path::PathBuf;

const BATCH_NUMBER: u64 = 42;
const BLOCK_NUMBER: u64 = 1234;

fn guest_dist() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}

/// Same helper as `end_to_end.rs`: slice `params_bytes` off the
/// front of a scenario's witness bytes.
fn scenario_to_prove_request(s: &scenarios::Scenario) -> ProveRequest {
    use prividium_sd_core::params::{
        BalanceOfParams, ObservableBytecodeHashParams, TxInclusionParams,
    };
    let params_len = match s.statement_id {
        StatementId::BalanceOf => BalanceOfParams::ENCODED_SIZE,
        StatementId::ObservableBytecodeHash => ObservableBytecodeHashParams::ENCODED_SIZE,
        StatementId::TxInclusion => TxInclusionParams::ENCODED_SIZE,
    };
    let header_len = 8 + 32;
    let params_bytes = s.witness_bytes[header_len..header_len + params_len].to_vec();
    ProveRequest {
        statement_id: s.statement_id,
        batch_number: s.batch_number,
        l1_commitment: s.l1_commitment,
        params_bytes,
        witness_bytes: s.witness_bytes.clone(),
    }
}

#[test]
fn mock_source_balance_of_end_to_end() {
    let addr_bytes = [0xabu8; 20];
    let balance_low: u64 = 0xdead_beef;
    let scenario =
        scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr_bytes, balance_low);
    let prove_request = scenario_to_prove_request(&scenario);

    let address = Address::from(addr_bytes);
    let disclosure = DisclosureRequest::BalanceOf {
        batch_number: BATCH_NUMBER,
        address,
    };
    let source = MockWitnessSource::new().with_request(&disclosure, prove_request);

    let bundle = prove_from_source(guest_dist(), &source, disclosure).expect("prove_from_source");

    let l1 = MockL1Source::new().with_batch(scenario.batch_number, scenario.l1_commitment);
    let verified = verify_bundle(guest_dist(), &bundle, &l1).expect("verify_bundle");

    match verified {
        VerifiedDisclosure::BalanceOf {
            batch_number,
            params,
            ..
        } => {
            assert_eq!(batch_number, BATCH_NUMBER);
            assert_eq!(params.address, addr_bytes);
            assert_eq!(&params.balance[24..], &balance_low.to_be_bytes());
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn mock_source_observable_bytecode_hash_end_to_end() {
    let addr_bytes = [0xcdu8; 20];
    let hash = [0xbeu8; 32];
    let scenario =
        scenarios::observable_bytecode_hash_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr_bytes, hash);
    let prove_request = scenario_to_prove_request(&scenario);

    let address = Address::from(addr_bytes);
    let disclosure = DisclosureRequest::ObservableBytecodeHash {
        batch_number: BATCH_NUMBER,
        address,
    };
    let source = MockWitnessSource::new().with_request(&disclosure, prove_request);

    let bundle = prove_from_source(guest_dist(), &source, disclosure).expect("prove_from_source");

    let l1 = MockL1Source::new().with_batch(scenario.batch_number, scenario.l1_commitment);
    let verified = verify_bundle(guest_dist(), &bundle, &l1).expect("verify_bundle");

    match verified {
        VerifiedDisclosure::ObservableBytecodeHash { params, .. } => {
            assert_eq!(params.address, addr_bytes);
            assert_eq!(params.observable_bytecode_hash, hash);
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn mock_source_tx_inclusion_end_to_end() {
    use alloy::primitives::B256;

    let tip: u64 = 2_000;
    let target_index: u32 = 100;
    let tx_hashes = vec![[0x01u8; 32], [0x02u8; 32], [0x03u8; 32], [0x04u8; 32]];
    let tx_index: u32 = 2;
    let scenario = scenarios::tx_inclusion_scenario(
        BATCH_NUMBER,
        tip,
        target_index,
        tx_hashes.clone(),
        tx_index,
    );
    let prove_request = scenario_to_prove_request(&scenario);

    let disclosure = DisclosureRequest::TxInclusion {
        batch_number: BATCH_NUMBER,
        tx_hash: B256::from(tx_hashes[tx_index as usize]),
    };
    let source = MockWitnessSource::new().with_request(&disclosure, prove_request);

    let bundle = prove_from_source(guest_dist(), &source, disclosure).expect("prove_from_source");

    let l1 = MockL1Source::new().with_batch(scenario.batch_number, scenario.l1_commitment);
    let verified = verify_bundle(guest_dist(), &bundle, &l1).expect("verify_bundle");

    match verified {
        VerifiedDisclosure::TxInclusion { params, .. } => {
            let expected_block_number = tip - 255 + target_index as u64;
            assert_eq!(params.block_number, expected_block_number);
            assert_eq!(params.tx_hash, tx_hashes[tx_index as usize]);
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn mock_source_returns_not_found_for_unregistered_request() {
    let source = MockWitnessSource::new();
    let disclosure = DisclosureRequest::BalanceOf {
        batch_number: 1,
        address: Address::ZERO,
    };
    let err = prove_from_source(guest_dist(), &source, disclosure).unwrap_err();
    // Error should be a Witness error (from the mock), not a Prove error.
    match err {
        prividium_sd_host::ProveFromSourceError::Witness(_) => {}
        other => panic!("expected Witness error, got {other:?}"),
    }
}

//! End-to-end prover → bundle → verifier tests.
//!
//! Each test:
//! 1. Builds a [`prividium_sd_test_fixtures::scenarios::Scenario`]
//!    (which contains the witness bytes, public params, batch
//!    number, L1 commitment, and expected public input).
//! 2. Translates it into a [`prividium_sd_host::ProveRequest`] and
//!    calls [`prividium_sd_host::prove`] to get a [`ProofBundle`].
//! 3. Encodes + decodes the bundle to exercise the wire format.
//! 4. Builds a [`prividium_sd_host::MockL1Source`] that knows the
//!    scenario's batch → L1 commitment mapping.
//! 5. Calls [`prividium_sd_host::verify_bundle`] and asserts the
//!    returned [`prividium_sd_host::VerifiedDisclosure`] matches
//!    the original scenario's public fields.
//!
//! # Prerequisite
//!
//! The guest binary must be pre-built under `../guest/dist/app/`:
//!
//! ```sh
//! (cd guest && cargo airbender build)
//! ```

use prividium_sd_core::params::{
    BalanceOfParams, ObservableBytecodeHashParams, TxInclusionParams,
};
use prividium_sd_core::statement_id::StatementId;
use prividium_sd_host::{
    prove, verify_bundle, MockL1Source, ProofBundle, ProveRequest, VerifiedDisclosure,
};
use prividium_sd_test_fixtures::scenarios;
use std::path::PathBuf;

const BATCH_NUMBER: u64 = 42;
const BLOCK_NUMBER: u64 = 1234;

fn guest_dist() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}

/// Strip the prover-side public header off a scenario's witness
/// bytes and pull out its statement-specific params bytes.
///
/// The witness bytes begin with the same `(batch_number ||
/// l1_commitment || params)` header that the pub-input commitment
/// uses; for the prover we need `params_bytes` separately so we can
/// stash them in the bundle and reconstruct the public input on the
/// verifier side without re-parsing the witness.
fn scenario_to_prove_request(s: &scenarios::Scenario) -> ProveRequest {
    // For each statement, the public params layout after the
    // `(batch_number:8 || l1_commitment:32)` header matches
    // `<statement>Params::to_bytes()` exactly. See the witness
    // `encode()` implementations in `prividium-sd-core::statements`.
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

fn run_round_trip(scenario: &scenarios::Scenario) -> (ProofBundle, VerifiedDisclosure) {
    // 1. Prove.
    let request = scenario_to_prove_request(scenario);
    let bundle = prove(guest_dist(), request).expect("prove");

    // 2. Sanity-check encode/decode.
    let bytes = bundle.encode().expect("bundle encode");
    let decoded = ProofBundle::decode(&bytes).expect("bundle decode");
    assert_eq!(decoded.statement_id_raw, bundle.statement_id_raw);
    assert_eq!(decoded.batch_number, bundle.batch_number);
    assert_eq!(decoded.l1_commitment, bundle.l1_commitment);
    assert_eq!(decoded.params_bytes, bundle.params_bytes);

    // 3. Verify.
    let l1 = MockL1Source::new().with_batch(scenario.batch_number, scenario.l1_commitment);
    let disclosure = verify_bundle(guest_dist(), &decoded, &l1).expect("verify_bundle");

    (bundle, disclosure)
}

#[test]
fn balance_of_existing_round_trip() {
    let addr = [0xabu8; 20];
    let balance_low: u64 = 0xdead_beef;
    let scenario = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, balance_low);

    let (_bundle, disclosure) = run_round_trip(&scenario);

    match disclosure {
        VerifiedDisclosure::BalanceOf {
            batch_number,
            l1_commitment,
            params,
        } => {
            assert_eq!(batch_number, BATCH_NUMBER);
            assert_eq!(l1_commitment, scenario.l1_commitment);
            assert_eq!(params.address, addr);
            // Check the low-64 bits of the balance.
            assert_eq!(&params.balance[24..], &balance_low.to_be_bytes());
        }
        other => panic!("unexpected disclosure variant: {other:?}"),
    }
}

#[test]
fn balance_of_non_existing_round_trip() {
    let absent = [0x77u8; 20];
    let scenario = scenarios::balance_of_non_existing_scenario(BATCH_NUMBER, BLOCK_NUMBER, absent);

    let (_bundle, disclosure) = run_round_trip(&scenario);

    match disclosure {
        VerifiedDisclosure::BalanceOf { params, .. } => {
            assert_eq!(params.address, absent);
            assert_eq!(params.balance, [0u8; 32]);
        }
        other => panic!("unexpected disclosure variant: {other:?}"),
    }
}

#[test]
fn observable_bytecode_hash_round_trip() {
    let addr = [0xcdu8; 20];
    let expected_hash = [0xbeu8; 32];
    let scenario = scenarios::observable_bytecode_hash_scenario(
        BATCH_NUMBER,
        BLOCK_NUMBER,
        addr,
        expected_hash,
    );

    let (_bundle, disclosure) = run_round_trip(&scenario);

    match disclosure {
        VerifiedDisclosure::ObservableBytecodeHash { params, .. } => {
            assert_eq!(params.address, addr);
            assert_eq!(params.observable_bytecode_hash, expected_hash);
        }
        other => panic!("unexpected disclosure variant: {other:?}"),
    }
}

#[test]
fn tx_inclusion_round_trip() {
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

    let (_bundle, disclosure) = run_round_trip(&scenario);

    match disclosure {
        VerifiedDisclosure::TxInclusion { params, .. } => {
            let expected_block_number = tip - 255 + target_index as u64;
            assert_eq!(params.block_number, expected_block_number);
            assert_eq!(params.tx_hash, tx_hashes[tx_index as usize]);
        }
        other => panic!("unexpected disclosure variant: {other:?}"),
    }
}

/// The verifier must reject a bundle whose `l1_commitment` does not
/// match what the L1 source returns for that batch.
#[test]
fn verifier_rejects_wrong_l1_commitment() {
    let addr = [0xabu8; 20];
    let scenario = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, 100);
    let request = scenario_to_prove_request(&scenario);
    let bundle = prove(guest_dist(), request).expect("prove");

    // Register a DIFFERENT L1 commitment for the same batch number.
    let mut wrong = scenario.l1_commitment;
    wrong[0] ^= 0xff;
    let l1 = MockL1Source::new().with_batch(scenario.batch_number, wrong);

    let err = verify_bundle(guest_dist(), &bundle, &l1).unwrap_err();
    assert!(
        matches!(
            err,
            prividium_sd_host::VerifyError::L1CommitmentMismatch { .. }
        ),
        "expected L1CommitmentMismatch, got {err:?}"
    );
}

/// If the L1 source has nothing for this batch, verification must
/// fail with an L1Source error rather than silently accepting.
#[test]
fn verifier_rejects_missing_batch() {
    let addr = [0xabu8; 20];
    let scenario = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, 100);
    let request = scenario_to_prove_request(&scenario);
    let bundle = prove(guest_dist(), request).expect("prove");

    let l1 = MockL1Source::new(); // empty

    let err = verify_bundle(guest_dist(), &bundle, &l1).unwrap_err();
    assert!(
        matches!(err, prividium_sd_host::VerifyError::L1Source(_)),
        "expected L1Source error, got {err:?}"
    );
}

/// Tamper with the bundle's `params_bytes` after the fact: this
/// should cause the reconstructed public-input commitment to no
/// longer match what the prover committed, and the airbender verifier
/// should reject.
#[test]
fn verifier_rejects_tampered_params() {
    let addr = [0xabu8; 20];
    let scenario = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, 100);
    let request = scenario_to_prove_request(&scenario);
    let mut bundle = prove(guest_dist(), request).expect("prove");

    // Flip a bit in the address inside `params_bytes`.
    bundle.params_bytes[0] ^= 0x01;

    let l1 = MockL1Source::new().with_batch(scenario.batch_number, scenario.l1_commitment);
    let err = verify_bundle(guest_dist(), &bundle, &l1).unwrap_err();
    assert!(
        matches!(err, prividium_sd_host::VerifyError::Airbender(_)),
        "expected Airbender verification error, got {err:?}"
    );
}

/// A guest asked to prove a witness with a tampered balance must
/// reject it. The rejection can come from two places:
///
/// - `ProveError::NativePreCheck(...)` when the `prove()` helper's
///   native pre-verification catches the problem first (the fast
///   path — this is what actually runs in practice).
/// - `ProveError::GuestRejected` if someone bypasses the pre-check
///   (e.g. via `prove_with_program` on a non-instrumented prover).
///
/// Either is acceptable here — the point of the test is that the
/// tampered witness never produces a valid proof bundle.
#[test]
fn prover_rejects_tampered_witness_balance() {
    let addr = [0xabu8; 20];
    let scenario = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, 100);
    let mut request = scenario_to_prove_request(&scenario);
    // Tamper the public balance inside the witness_bytes header.
    // Layout: batch_number(8) + l1_commitment(32) + address(20) + balance(32)
    let balance_offset = 8 + 32 + 20;
    request.witness_bytes[balance_offset + 31] ^= 0x01;

    let err = prove(guest_dist(), request).unwrap_err();
    assert!(
        matches!(
            err,
            prividium_sd_host::ProveError::GuestRejected
                | prividium_sd_host::ProveError::NativePreCheck(_)
        ),
        "expected GuestRejected or NativePreCheck, got {err:?}"
    );
}

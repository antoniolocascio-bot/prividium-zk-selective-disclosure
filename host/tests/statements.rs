//! End-to-end integration tests: build each scenario via
//! `prividium-sd-test-fixtures`, push it through the airbender guest,
//! and assert the guest committed the expected public-input
//! commitment.
//!
//! # Prerequisite
//!
//! The guest binary must be pre-built under `../guest/dist/app/`. From
//! the repository root:
//!
//! ```sh
//! (cd guest && cargo airbender build)
//! ```
//!
//! Any time the guest or the `core` crate changes, re-run that
//! command before running these tests. The tests will fail with a
//! clear "Program::load failed" error if the artifacts are missing or
//! stale.

use airbender_host::{Inputs, Program, Runner};
use prividium_sd_core::pub_input;
use prividium_sd_test_fixtures::scenarios;
use std::path::PathBuf;

const BATCH_NUMBER: u64 = 42;
const BLOCK_NUMBER: u64 = 1234;

fn load_program() -> Program {
    let dist_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app");
    Program::load(&dist_dir).expect(
        "failed to load guest artifacts; run `cd guest && cargo airbender build` first",
    )
}

/// Push `(statement_id as u32, witness_bytes)` into an `Inputs`
/// buffer, run the guest via the transpiler runner, and return the
/// 8-word receipt output.
fn run_scenario(scenario: &scenarios::Scenario) -> [u32; 8] {
    let program = load_program();

    let mut inputs = Inputs::new();
    inputs.push(&(scenario.statement_id as u32)).unwrap();
    inputs.push(&scenario.witness_bytes).unwrap();

    let runner = program
        .transpiler_runner()
        .with_cycles(16_000_000)
        .build()
        .expect("runner build");
    let execution = runner.run(inputs.words()).expect("guest execution");
    assert!(
        execution.reached_end,
        "guest did not reach exit_success; reached_end=false"
    );
    execution.receipt.output
}

#[test]
fn guest_runs_balance_of_existing() {
    let addr = [0xabu8; 20];
    let s = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, 0xdead_beef);

    let output = run_scenario(&s);
    let output_bytes = pub_input::unpack_from_words(&output);
    assert_eq!(output_bytes, s.expected_pub_input);
}

#[test]
fn guest_runs_balance_of_non_existing() {
    let absent = [0x77u8; 20];
    let s = scenarios::balance_of_non_existing_scenario(BATCH_NUMBER, BLOCK_NUMBER, absent);

    let output = run_scenario(&s);
    let output_bytes = pub_input::unpack_from_words(&output);
    assert_eq!(output_bytes, s.expected_pub_input);
}

#[test]
fn guest_runs_observable_bytecode_hash() {
    let addr = [0xcdu8; 20];
    let hash = [0xbeu8; 32];
    let s = scenarios::observable_bytecode_hash_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, hash);

    let output = run_scenario(&s);
    let output_bytes = pub_input::unpack_from_words(&output);
    assert_eq!(output_bytes, s.expected_pub_input);
}

#[test]
fn guest_runs_tx_inclusion() {
    let tip: u64 = 2_000;
    let target_index: u32 = 100;
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
        tx_hashes,
        tx_index,
    );

    let output = run_scenario(&s);
    let output_bytes = pub_input::unpack_from_words(&output);
    assert_eq!(output_bytes, s.expected_pub_input);
}

/// Flipping a byte of the public balance must cause the guest to
/// call `exit_error()`.
///
/// `airbender_rt::sys::exit_error` is implemented by writing to the
/// `cycle` CSR, which deliberately raises an illegal instruction so
/// that the airbender circuits end up unsatisfiable. The transpiler
/// runner surfaces that as a panic from inside `run(...)`, so the
/// only portable way to assert "the guest rejected this" from a
/// native test is to catch the panic and assert we got one.
#[test]
fn guest_rejects_tampered_balance() {
    let addr = [0xabu8; 20];
    let s = scenarios::balance_of_scenario(BATCH_NUMBER, BLOCK_NUMBER, addr, 100);
    let mut bytes = s.witness_bytes.clone();
    // Tamper the public balance (offset 8 + 32 + 20, 32 bytes).
    bytes[60 + 31] ^= 0x01;

    let statement_id = s.statement_id;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let program = load_program();
        let mut inputs = Inputs::new();
        inputs.push(&(statement_id as u32)).unwrap();
        inputs.push(&bytes).unwrap();
        let runner = program
            .transpiler_runner()
            .with_cycles(16_000_000)
            .build()
            .expect("runner build");
        runner.run(inputs.words()).expect("guest execution")
    }));
    assert!(
        result.is_err(),
        "guest must have hit exit_error on tampered balance; \
         got successful execution result instead"
    );
}

//! Prover entry point.
//!
//! The primary API is [`prove`], which takes a low-level
//! [`ProveRequest`] (statement id + public params + encoded witness
//! bytes) and returns a [`ProofBundle`]. The request carries already-
//! built witness bytes, so this module has no knowledge of RPC
//! fetching; a higher-level "build a witness from RPC" layer will
//! live elsewhere once the RPC clients land.
//!
//! The witness bytes are expected to be in the exact binary format
//! [`prividium_sd_core::statements::*::*Witness::encode`] produces.
//! The prover does not re-validate them itself — the guest will
//! reject anything invalid via `exit_error()`, which surfaces as a
//! runner panic and a clean `ProveError::GuestRejected`.
//!
//! Currently wired to the **dev** backend. The bundle records this
//! via [`ProofBundle::dev_only`] so the verifier knows to pass the
//! input words through.

use crate::bundle::{DevOnlyFields, ProofBundle};
use airbender_host::{Inputs, Program, Prover, Result as HostResult};
use prividium_sd_core::statement_id::StatementId;
use std::path::Path;

/// What the caller wants to prove.
///
/// The `params_bytes` and `witness_bytes` are both in the canonical
/// binary format defined by `prividium-sd-core`. Callers typically
/// build both by calling `.to_bytes()` on a typed
/// `prividium_sd_core::params::*Params` struct and `.encode()` on a
/// typed `prividium_sd_core::statements::*::*Witness` struct.
#[derive(Clone, Debug)]
pub struct ProveRequest {
    /// Which statement the witness is for.
    pub statement_id: StatementId,
    /// L1 batch number the proof is relative to.
    pub batch_number: u64,
    /// The L1 commitment (`storedBatchHash(batch_number)`) the
    /// witness was built against. The prover trusts the witness to
    /// be consistent with this — the guest will reject if not.
    pub l1_commitment: [u8; 32],
    /// Canonical public-parameter byte layout for this statement.
    pub params_bytes: Vec<u8>,
    /// Witness bytes in the canonical per-statement binary format.
    pub witness_bytes: Vec<u8>,
}

/// Errors returned by [`prove`].
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error("airbender host error: {0}")]
    Airbender(#[from] airbender_host::HostError),
    /// Propagated when the airbender runner panics from inside
    /// `runner.run(...)` — most commonly because the guest called
    /// `exit_error()` on an invalid witness.
    #[error("guest rejected the witness (runner panicked)")]
    GuestRejected,
}

/// Generate a [`ProofBundle`] by running the airbender dev prover on
/// the given request.
///
/// `guest_dist_path` is the path to the `dist/app` directory that
/// `cargo airbender build` produces (containing `app.bin`, `app.elf`,
/// `app.text`, `manifest.toml`).
pub fn prove(
    guest_dist_path: impl AsRef<Path>,
    request: ProveRequest,
) -> Result<ProofBundle, ProveError> {
    let program = Program::load(guest_dist_path.as_ref())?;
    prove_with_program(&program, request)
}

/// Same as [`prove`], but accepts a pre-loaded [`Program`] so tests
/// can reuse one guest binary across many scenarios without paying
/// the load cost per invocation.
pub fn prove_with_program(
    program: &Program,
    request: ProveRequest,
) -> Result<ProofBundle, ProveError> {
    let mut inputs = Inputs::new();
    inputs.push(&(request.statement_id as u32))?;
    inputs.push(&request.witness_bytes)?;

    // Build + run the dev prover.
    //
    // We snapshot `inputs.words()` before the `prove` call so that
    // the bundle carries the exact `[u32]` stream the dev verifier
    // will later need to re-hash as `input_words_hash`.
    let input_words: Vec<u32> = inputs.words().to_vec();

    // `DevProver::prove` deep-inside calls the transpiler runner,
    // which panics on illegal instructions (including the
    // `exit_error()` CSR write). Catch the panic and translate it
    // into a clean `GuestRejected` error so callers do not have to
    // plumb `catch_unwind` through their own code.
    let prover_builder = program.dev_prover();
    let prover = prover_builder.build()?;

    let prove_result = run_prover_catching_panic(&prover, &input_words)?;

    Ok(ProofBundle {
        statement_id_raw: request.statement_id as u32,
        batch_number: request.batch_number,
        l1_commitment: request.l1_commitment,
        params_bytes: request.params_bytes,
        proof: prove_result.proof,
        dev_only: Some(DevOnlyFields { input_words }),
    })
}

fn run_prover_catching_panic(
    prover: &airbender_host::DevProver,
    input_words: &[u32],
) -> Result<airbender_host::ProveResult, ProveError> {
    // DevProver is not `UnwindSafe` in general, but all we're going
    // to do on a panic is drop the result and return an error, so
    // `AssertUnwindSafe` is safe here: we make no observation of
    // `prover`'s state after the panic.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(input_words)));
    match result {
        Ok(Ok(prove_result)) => Ok(prove_result),
        Ok(Err(host_err)) => Err(ProveError::Airbender(host_err)),
        Err(_) => Err(ProveError::GuestRejected),
    }
}

/// Convenience shim that just forwards the `Inputs::push` result into
/// our error type. Kept as a standalone helper so the error mapping
/// stays out of the main prove path.
#[inline]
#[allow(dead_code)]
fn push<T: serde::Serialize>(inputs: &mut Inputs, value: &T) -> HostResult<()> {
    inputs.push(value)
}

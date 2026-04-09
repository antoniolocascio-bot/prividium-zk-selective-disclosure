//! Verifier entry point.
//!
//! [`verify_bundle`] takes a [`ProofBundle`], an [`L1Source`], and a
//! path to the guest `dist/app` directory. It:
//!
//! 1. Queries the L1 source for `storedBatchHash(bundle.batch_number)`.
//! 2. Checks the returned commitment matches `bundle.l1_commitment`.
//!    If not, the bundle is attempting to bind itself to a fake or
//!    wrong batch and we bail out immediately.
//! 3. Reconstructs the expected public-input commitment
//!    `keccak256(statement_id || batch_number || l1_commitment ||
//!    params_bytes)` from the bundle's typed fields.
//! 4. Loads the VK from the guest binary and calls
//!    [`airbender_host::Verifier::verify`] with the expected input
//!    words (from `bundle.dev_only`) and the expected 32-byte output
//!    packed as `[u32; 8]`.
//! 5. Returns a [`VerifiedDisclosure`] describing the verified claim
//!    in typed form so callers can surface it to the user without
//!    having to re-decode the bundle.

use crate::bundle::{BundleError, ProofBundle};
use crate::l1_source::L1Source;
use airbender_host::{Program, VerificationRequest, Verifier as _};
use prividium_sd_core::params::{
    BalanceOfParams, ObservableBytecodeHashParams, TxInclusionParams,
};
use prividium_sd_core::pub_input;
use prividium_sd_core::statement_id::StatementId;
use std::path::Path;

/// Structured description of what a successfully-verified bundle has
/// attested to. Returned by [`verify_bundle`] so the caller doesn't
/// have to re-parse `params_bytes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedDisclosure {
    BalanceOf {
        batch_number: u64,
        l1_commitment: [u8; 32],
        params: BalanceOfParams,
    },
    ObservableBytecodeHash {
        batch_number: u64,
        l1_commitment: [u8; 32],
        params: ObservableBytecodeHashParams,
    },
    TxInclusion {
        batch_number: u64,
        l1_commitment: [u8; 32],
        params: TxInclusionParams,
    },
}

impl VerifiedDisclosure {
    pub fn statement_id(&self) -> StatementId {
        match self {
            Self::BalanceOf { .. } => StatementId::BalanceOf,
            Self::ObservableBytecodeHash { .. } => StatementId::ObservableBytecodeHash,
            Self::TxInclusion { .. } => StatementId::TxInclusion,
        }
    }

    pub fn batch_number(&self) -> u64 {
        match self {
            Self::BalanceOf { batch_number, .. }
            | Self::ObservableBytecodeHash { batch_number, .. }
            | Self::TxInclusion { batch_number, .. } => *batch_number,
        }
    }

    pub fn l1_commitment(&self) -> &[u8; 32] {
        match self {
            Self::BalanceOf { l1_commitment, .. }
            | Self::ObservableBytecodeHash { l1_commitment, .. }
            | Self::TxInclusion { l1_commitment, .. } => l1_commitment,
        }
    }
}

/// All the ways [`verify_bundle`] can reject.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("bundle format error: {0}")]
    Bundle(#[from] BundleError),
    #[error("airbender host error: {0}")]
    Airbender(#[from] airbender_host::HostError),
    #[error("l1 source error: {0}")]
    L1Source(Box<dyn std::error::Error + Send + Sync>),
    #[error(
        "bundle L1 commitment does not match storedBatchHash(batch_number): bundle={bundle_hex:?}, l1={l1_hex:?}"
    )]
    L1CommitmentMismatch {
        bundle_hex: String,
        l1_hex: String,
    },
    #[error("dev-backend bundle is missing its input_words field")]
    MissingDevInputWords,
    #[error("bundle params_bytes has wrong length for {statement:?}: expected {expected}, got {actual}")]
    InvalidParamsLength {
        statement: StatementId,
        expected: usize,
        actual: usize,
    },
}

/// Verify a bundle end-to-end.
pub fn verify_bundle<L: L1Source>(
    guest_dist_path: impl AsRef<Path>,
    bundle: &ProofBundle,
    l1_source: &L,
) -> Result<VerifiedDisclosure, VerifyError> {
    // 1. L1 check.
    let onchain = l1_source
        .stored_batch_hash(bundle.batch_number)
        .map_err(|err| VerifyError::L1Source(Box::new(err)))?;
    if onchain != bundle.l1_commitment {
        return Err(VerifyError::L1CommitmentMismatch {
            bundle_hex: hex32(&bundle.l1_commitment),
            l1_hex: hex32(&onchain),
        });
    }

    // 2. Decode the statement id up front.
    let statement_id = bundle.statement_id()?;

    // 3. Recompute the expected 32-byte public input from the
    //    bundle's public fields.
    let pub_input_bytes = pub_input::compute_raw(
        statement_id,
        bundle.batch_number,
        &bundle.l1_commitment,
        &bundle.params_bytes,
    );
    let pub_input_words = pub_input::pack_to_words(&pub_input_bytes);

    // 4. Load the guest binary and run airbender verification.
    let program = Program::load(guest_dist_path.as_ref())?;
    let verifier = program.dev_verifier().build()?;
    let vk = verifier.generate_vk()?;

    let dev_fields = bundle
        .dev_only
        .as_ref()
        .ok_or(VerifyError::MissingDevInputWords)?;

    verifier.verify(
        &bundle.proof,
        &vk,
        VerificationRequest::dev(&dev_fields.input_words, &pub_input_words),
    )?;

    // 5. Decode params into the typed "what was proved" surface.
    decode_disclosure(statement_id, bundle)
}

fn decode_disclosure(
    statement_id: StatementId,
    bundle: &ProofBundle,
) -> Result<VerifiedDisclosure, VerifyError> {
    match statement_id {
        StatementId::BalanceOf => {
            let params = decode_balance_of_params(&bundle.params_bytes)?;
            Ok(VerifiedDisclosure::BalanceOf {
                batch_number: bundle.batch_number,
                l1_commitment: bundle.l1_commitment,
                params,
            })
        }
        StatementId::ObservableBytecodeHash => {
            let params = decode_obh_params(&bundle.params_bytes)?;
            Ok(VerifiedDisclosure::ObservableBytecodeHash {
                batch_number: bundle.batch_number,
                l1_commitment: bundle.l1_commitment,
                params,
            })
        }
        StatementId::TxInclusion => {
            let params = decode_tx_inclusion_params(&bundle.params_bytes)?;
            Ok(VerifiedDisclosure::TxInclusion {
                batch_number: bundle.batch_number,
                l1_commitment: bundle.l1_commitment,
                params,
            })
        }
    }
}

fn decode_balance_of_params(bytes: &[u8]) -> Result<BalanceOfParams, VerifyError> {
    if bytes.len() != BalanceOfParams::ENCODED_SIZE {
        return Err(VerifyError::InvalidParamsLength {
            statement: StatementId::BalanceOf,
            expected: BalanceOfParams::ENCODED_SIZE,
            actual: bytes.len(),
        });
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes[..20]);
    let mut balance = [0u8; 32];
    balance.copy_from_slice(&bytes[20..]);
    Ok(BalanceOfParams { address, balance })
}

fn decode_obh_params(bytes: &[u8]) -> Result<ObservableBytecodeHashParams, VerifyError> {
    if bytes.len() != ObservableBytecodeHashParams::ENCODED_SIZE {
        return Err(VerifyError::InvalidParamsLength {
            statement: StatementId::ObservableBytecodeHash,
            expected: ObservableBytecodeHashParams::ENCODED_SIZE,
            actual: bytes.len(),
        });
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes[..20]);
    let mut observable_bytecode_hash = [0u8; 32];
    observable_bytecode_hash.copy_from_slice(&bytes[20..]);
    Ok(ObservableBytecodeHashParams {
        address,
        observable_bytecode_hash,
    })
}

fn decode_tx_inclusion_params(bytes: &[u8]) -> Result<TxInclusionParams, VerifyError> {
    if bytes.len() != TxInclusionParams::ENCODED_SIZE {
        return Err(VerifyError::InvalidParamsLength {
            statement: StatementId::TxInclusion,
            expected: TxInclusionParams::ENCODED_SIZE,
            actual: bytes.len(),
        });
    }
    let mut bn = [0u8; 8];
    bn.copy_from_slice(&bytes[..8]);
    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(&bytes[8..]);
    Ok(TxInclusionParams {
        block_number: u64::from_be_bytes(bn),
        tx_hash,
    })
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(2 + 64);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

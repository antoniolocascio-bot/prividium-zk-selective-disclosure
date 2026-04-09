//! Wire format for shipping a selective-disclosure proof from a
//! prover to a verifier.
//!
//! A [`ProofBundle`] is what a disclosing party hands to a verifier.
//! It contains everything the verifier needs to reconstruct the
//! expected public input and call the airbender verifier — except
//! the trust root itself (`storedBatchHash(batch_number)` on L1),
//! which the verifier must fetch independently.
//!
//! # Versioning
//!
//! The bundle is prefixed with a version byte ([`BUNDLE_FORMAT_VERSION`])
//! so we can evolve the payload without breaking old decoders. Any
//! future format must be additive or introduce a new version; decoders
//! reject bundles with an unknown version rather than trying to
//! interpret them.
//!
//! # On-wire encoding
//!
//! The bundle uses `postcard`, the same serde-compatible format used
//! across the Rust embedded ecosystem. The airbender `Proof` type is
//! itself `Serialize + Deserialize` so we just wrap it. Alternatives
//! considered: `bincode` (works, but more fragile around feature
//! flags) and `serde_json` (debuggable, but significantly larger for
//! the dev-proof receipt). Postcard strikes the right balance for a
//! proof bundle that will be transmitted over the wire.

use airbender_host::Proof;
use prividium_sd_core::statement_id::{StatementId, StatementIdError};
use serde::{Deserialize, Serialize};

/// Current bundle format version. Bump on any breaking change.
pub const BUNDLE_FORMAT_VERSION: u8 = 1;

/// Errors returned by [`ProofBundle::encode`] / [`ProofBundle::decode`].
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("postcard serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
    #[error(
        "unsupported bundle format version: expected {expected}, got {actual}"
    )]
    UnsupportedVersion { expected: u8, actual: u8 },
    #[error("unknown statement id in bundle: {0}")]
    UnknownStatementId(u32),
    #[error("bundle is empty")]
    Empty,
}

/// Fully self-describing proof envelope.
///
/// The fields correspond one-to-one with the public-input commitment
/// derivation in [`prividium_sd_core::pub_input`]:
///
/// ```text
/// pub_input = keccak256(
///       statement_id.to_be_bytes(4)
///    || batch_number.to_be_bytes(8)
///    || l1_commitment
///    || params_bytes                         // statement-specific layout
/// )
/// ```
///
/// The verifier reconstructs `pub_input` from `(statement_id,
/// batch_number, l1_commitment, params_bytes)` exactly, and then
/// calls the airbender verifier to check that the attached proof
/// committed that 32-byte value as its output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    /// `StatementId` as a `u32` tag. We store the raw value rather
    /// than the enum so an unknown tag shows up as a clean decode
    /// error (rather than a panic in a naive enum deserializer).
    pub statement_id_raw: u32,
    /// L1 batch number the proof is relative to.
    pub batch_number: u64,
    /// Expected `storedBatchHash(batch_number)` from the diamond
    /// proxy. The verifier re-fetches this from L1 and rejects the
    /// bundle if it does not match.
    pub l1_commitment: [u8; 32],
    /// Canonical, statement-specific public-parameter bytes — the
    /// exact sequence that gets hashed into the public-input
    /// commitment. See
    /// [`prividium_sd_core::params`] for the layouts.
    pub params_bytes: Vec<u8>,
    /// The airbender proof envelope. Serde-serializable via
    /// airbender-host's own implementation.
    pub proof: Proof,
    /// Dev-only payload: the exact `[u32]` input-word stream the
    /// prover fed to the guest, needed by [`airbender_host::DevVerifier`]
    /// to check `input_words_hash`. The real verifier ignores this.
    ///
    /// `Some(..)` for dev-backend bundles, `None` for real-backend
    /// bundles (once we support those).
    pub dev_only: Option<DevOnlyFields>,
}

/// Extra fields the dev backend needs but the real backend does not.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevOnlyFields {
    pub input_words: Vec<u32>,
}

impl ProofBundle {
    /// Deserialize the `statement_id_raw` into a typed enum, rejecting
    /// unknown values as a decode error.
    pub fn statement_id(&self) -> Result<StatementId, BundleError> {
        StatementId::try_from(self.statement_id_raw).map_err(|StatementIdError::Unknown(v)| {
            BundleError::UnknownStatementId(v)
        })
    }

    /// Serialize to a wire format byte string.
    ///
    /// Layout: `[ version_byte, postcard(self) ]`.
    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        let body = postcard::to_allocvec(self)?;
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(BUNDLE_FORMAT_VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Deserialize from the wire format. Rejects unknown versions
    /// and unknown statement IDs up front.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        let (&version, body) = bytes.split_first().ok_or(BundleError::Empty)?;
        if version != BUNDLE_FORMAT_VERSION {
            return Err(BundleError::UnsupportedVersion {
                expected: BUNDLE_FORMAT_VERSION,
                actual: version,
            });
        }
        let bundle: Self = postcard::from_bytes(body)?;
        // Validate the statement_id eagerly so callers never see an
        // unknown enum tag downstream.
        let _ = bundle.statement_id()?;
        Ok(bundle)
    }
}

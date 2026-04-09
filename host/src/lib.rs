//! Prover and verifier host for Prividium selective-disclosure proofs.
//!
//! This crate provides library-level `prove` and `verify` entry points
//! that drive the airbender guest and wrap its output in a
//! serializable [`bundle::ProofBundle`]. The intent is that a future
//! CLI or network service can layer on top of these functions by
//! supplying RPC clients as [`l1_source::L1Source`] implementations
//! (and, for proving, a way to fetch a witness — see
//! [`prover::ProveRequest`]).
//!
//! # Dev vs. real backends
//!
//! Everything here is currently wired to the airbender **dev**
//! backend (`DevProver` / `DevVerifier`). The bundle format and
//! public API are designed so that a future switch to the real
//! (GPU / CPU) backend is additive — see [`bundle::ProofBundle::dev_only`]
//! for the only dev-specific field (the input-word list required by
//! the dev verifier). When we move to real proofs, the prover will
//! leave that field empty and the verifier will skip the
//! dev-specific check.
//!
//! # Threat model
//!
//! The verifier trusts the L1 source to return the canonical
//! `storedBatchHash(batch_number)` for the diamond proxy. The prover
//! trusts nothing — it re-derives the L1 commitment inside the guest
//! and rejects any witness that does not match the public parameters.

pub mod bundle;
pub mod l1_source;
pub mod prover;
pub mod verifier;

pub use bundle::{BundleError, ProofBundle, BUNDLE_FORMAT_VERSION};
pub use l1_source::{L1Source, MockL1Source};
pub use prover::{prove, ProveError, ProveRequest};
pub use verifier::{verify_bundle, VerifiedDisclosure, VerifyError};

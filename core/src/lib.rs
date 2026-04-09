//! `prividium-sd-core` — shared logic for Prividium selective-disclosure
//! proofs.
//!
//! This crate is `no_std` + `alloc` and is consumed by:
//!
//! - the airbender guest binary (`../guest`), which imports it to implement
//!   statement verification inside the riscv32 VM;
//! - native dev tooling (tests, future prover/verifier hosts), which imports
//!   it to build and decode witnesses.
//!
//! There must be exactly one implementation of every cryptographic and
//! encoding primitive in this crate, used unchanged by both sides. See
//! `DESIGN.md` / `PLAN.md` in the repository root for the full picture.

#![no_std]

extern crate alloc;

pub mod account_properties;
pub mod block_header;
pub mod hash;
pub mod params;
pub mod pub_input;
pub mod rlp;
pub mod state_commitment;
pub mod statement_id;
pub mod statements;
pub mod stored_batch_info;
pub mod tree;
pub mod tx_rolling_hash;
pub mod witness;

pub use statement_id::{StatementId, StatementIdError};

/// Placeholder smoke test so we can verify the crate compiles on both
/// native and `riscv32im-risc0-zkvm-elf` before any real logic lands.
/// TODO: remove once the guest uses a real statement entry point.
#[inline]
pub const fn ping() -> u32 {
    0
}

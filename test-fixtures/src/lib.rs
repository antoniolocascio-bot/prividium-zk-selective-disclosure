#![feature(allocator_api)]

//! Native helpers for building selective-disclosure witnesses in tests.
//!
//! This crate is strictly `std`-only and is never compiled into the
//! airbender guest. Its job is to stand up realistic scenarios
//! (populated state trees, synthetic block sequences, fully
//! reconstructable L1 commitments) entirely in memory, so that guest
//! and statement-verifier tests can run without any RPC dependency.
//!
//! The tree-side fixtures wrap
//! `basic_system::system_implementation::flat_storage_model::TestingTree`,
//! which is the same in-memory Merkle tree used by
//! `forward_system`'s own tests. Using it here guarantees that every
//! proof we produce is byte-identical to what the real ZKsync OS server
//! would emit for the same inputs — there is no hand-rolled mock that
//! could drift from the reference implementation.

pub mod mock_block;
pub mod mock_tree;
pub mod scenarios;

pub use mock_block::{build_chain, build_window, BlockWindow, MockBlock};
pub use mock_tree::MockStateTree;
pub use scenarios::Scenario;

//! ZKsync OS state-tree primitives used by the selective-disclosure guest.
//!
//! The tree is a fixed-depth (64) binary Merkle tree over Blake2s-256, with
//! leaves linked in a sorted linked list by key order. The full reference is
//! `zksync-os/docs/system/io/tree.md` and
//! `zksync-os-server/docs/src/design/zks_getProof.md`.
//!
//! The guest verifies Merkle proofs that were produced by
//! `basic_system::flat_storage_model::TestingTree::get_proof_for_position`,
//! so the in-crate types mirror `basic_system::FlatStorageLeaf` and
//! `basic_system::LeafProof` field-for-field.

pub mod key;
pub mod merkle;

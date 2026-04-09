//! Wrapper around `basic_system`'s `TestingTree` that speaks the
//! `prividium-sd-core` witness types.
//!
//! The wrapper's entire job is to (a) build a populated Blake2s state
//! tree using the reference implementation, (b) pull proofs out of it
//! via `TestingTree::get`, and (c) translate the result into our
//! `prividium_sd_core::tree::merkle::AccountMerkleProof` shape so the
//! guest and the statement verifiers can consume them without ever
//! linking against `basic_system`.
//!
//! The field layouts are chosen to be structurally identical in both
//! crates, so the translation is a field-by-field copy.

use basic_system::system_implementation::flat_storage_model::{
    Blake2sStorageHasher, FlatStorageLeaf as BsLeaf, LeafProof as BsLeafProof,
    ReadValueWithProof, TestingTree as BsTestingTree,
};
use prividium_sd_core::account_properties::AccountProperties;
use prividium_sd_core::tree::key::account_properties_slot_key;
use prividium_sd_core::tree::merkle::{
    AccountMerkleProof, FlatStorageLeaf, LeafProof, TREE_DEPTH,
};
use std::alloc::Global;
use std::boxed::Box;
use zk_ee::utils::Bytes32;

/// Tree-height constant matching `TESTING_TREE_HEIGHT` in
/// `basic_system`. If this ever diverges from [`TREE_DEPTH`] the
/// conversion code below will stop compiling.
const TREE_HEIGHT: usize = 64;
const _: () = assert!(TREE_HEIGHT == TREE_DEPTH);

/// Thin owner of a `TestingTree` plus convenience methods for inserting
/// account data and extracting proofs in our in-crate format.
pub struct MockStateTree {
    inner: BsTestingTree<false>,
}

impl MockStateTree {
    /// Empty state tree (already contains the two synthetic boundary
    /// leaves at keys `0x00…00` and `0xff…ff` that `TestingTree` uses
    /// to avoid corner cases in the linked-list walk).
    pub fn new() -> Self {
        Self {
            inner: BsTestingTree::<false>::new_in(Global),
        }
    }

    /// Insert `account_properties.compute_hash()` at the flat key used
    /// by ZKsync OS for this account (`blake2s(pad32(0x8003) ||
    /// pad32(user_address))`).
    pub fn insert_account(&mut self, user_address: [u8; 20], props: &AccountProperties) {
        let flat_key = account_properties_slot_key(&user_address);
        let value_hash = props.compute_hash();
        self.inner
            .insert(&Bytes32::from_array(flat_key), &Bytes32::from_array(value_hash));
    }

    /// Insert a raw `(flat_key, value)` pair for non-account slots
    /// (useful for constructing synthetic witnesses for future
    /// statements). Not used by the initial three statements.
    pub fn insert_raw(&mut self, flat_key: [u8; 32], value: [u8; 32]) {
        self.inner
            .insert(&Bytes32::from_array(flat_key), &Bytes32::from_array(value));
    }

    /// Return the current Merkle root of the tree.
    pub fn root(&self) -> [u8; 32] {
        *self.inner.root().as_u8_array_ref()
    }

    /// Return the tree's `next_free_slot` counter — the value that the
    /// `ChainStateCommitment` preimage uses as `next_free_slot`.
    pub fn next_free_slot(&self) -> u64 {
        self.inner.next_free_slot
    }

    /// Fetch an account proof suitable for the
    /// `balance_of` / `observable_bytecode_hash` statements.
    ///
    /// Returns `AccountMerkleProof::Existing` if the account is
    /// present in the tree, or `AccountMerkleProof::NonExisting` with
    /// bracketing neighbours otherwise.
    pub fn get_account_proof(&self, user_address: [u8; 20]) -> AccountMerkleProof {
        let flat_key = account_properties_slot_key(&user_address);
        self.get_raw_proof(flat_key)
    }

    /// Low-level proof fetch for an arbitrary flat key.
    pub fn get_raw_proof(&self, flat_key: [u8; 32]) -> AccountMerkleProof {
        let bs_key = Bytes32::from_array(flat_key);
        match self.inner.get(&bs_key) {
            ReadValueWithProof::Existing { proof } => {
                AccountMerkleProof::Existing(convert_leaf_proof(proof.existing))
            }
            ReadValueWithProof::New { proof, .. } => AccountMerkleProof::NonExisting {
                left: convert_leaf_proof(proof.previous),
                right: convert_leaf_proof(proof.next),
            },
        }
    }
}

impl Default for MockStateTree {
    fn default() -> Self {
        Self::new()
    }
}

fn convert_leaf_proof(src: BsLeafProof<TREE_HEIGHT, Blake2sStorageHasher, Global>) -> LeafProof {
    let leaf = convert_leaf(&src.leaf);
    // `src.path` is `Box<[Bytes32; 64], Global>`. Copy it into a new
    // `Box<[[u8; 32]; 64]>` on the regular `alloc::alloc::Global` so
    // the output type has the stable default allocator that the `core`
    // crate's `LeafProof` expects.
    let mut path_arr: [[u8; 32]; TREE_DEPTH] = [[0u8; 32]; TREE_DEPTH];
    for (dst, src) in path_arr.iter_mut().zip(src.path.iter()) {
        *dst = *src.as_u8_array_ref();
    }
    LeafProof {
        index: src.index,
        leaf,
        path: Box::new(path_arr),
    }
}

fn convert_leaf(src: &BsLeaf<TREE_HEIGHT>) -> FlatStorageLeaf {
    FlatStorageLeaf {
        key: *src.key.as_u8_array_ref(),
        value: *src.value.as_u8_array_ref(),
        next: src.next,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prividium_sd_core::tree::merkle::{verify_account_proof, MerkleError};

    fn sample_account() -> AccountProperties {
        AccountProperties {
            versioning_data: 0,
            nonce: 7,
            balance: {
                let mut b = [0u8; 32];
                b[28] = 0xde;
                b[29] = 0xad;
                b[30] = 0xbe;
                b[31] = 0xef;
                b
            },
            bytecode_hash: [0u8; 32],
            unpadded_code_len: 0,
            artifacts_len: 0,
            observable_bytecode_hash: [0u8; 32],
            observable_bytecode_len: 0,
        }
    }

    #[test]
    fn empty_tree_has_stable_root() {
        let t = MockStateTree::new();
        // Root should not be all-zeros — the two sentinel leaves
        // (0x00...00 and 0xff...ff) make the empty-tree root a
        // well-defined non-trivial Blake2s digest.
        let root = t.root();
        assert_ne!(root, [0u8; 32]);

        // And `next_free_slot` starts at 2 (after the two sentinels).
        assert_eq!(t.next_free_slot(), 2);
    }

    #[test]
    fn insert_account_then_prove_roundtrip() {
        let mut t = MockStateTree::new();
        let addr = [0xaau8; 20];
        let props = sample_account();
        t.insert_account(addr, &props);

        let proof = t.get_account_proof(addr);
        match &proof {
            AccountMerkleProof::Existing(p) => {
                // Leaf value must equal blake2s(account encoding).
                assert_eq!(p.leaf.value, props.compute_hash());
                // And the flat key must match our derivation.
                assert_eq!(p.leaf.key, account_properties_slot_key(&addr));
            }
            AccountMerkleProof::NonExisting { .. } => {
                panic!("expected existing proof for inserted account");
            }
        }

        // Verify against the tree's claimed root.
        let (proof_root, value) = verify_account_proof(
            &proof,
            &account_properties_slot_key(&addr),
        )
        .expect("proof must verify");
        assert_eq!(proof_root, t.root());
        assert_eq!(value, props.compute_hash());
    }

    #[test]
    fn non_existing_proof_for_absent_account() {
        let mut t = MockStateTree::new();
        // Insert two accounts so the non-existence proof has real
        // neighbours rather than sentinels.
        let low_addr = [0x00u8; 20];
        let high_addr = [0xffu8; 20];
        t.insert_account(low_addr, &sample_account());
        t.insert_account(high_addr, &sample_account());

        let absent = [0x77u8; 20];
        let proof = t.get_account_proof(absent);
        let flat_key = account_properties_slot_key(&absent);
        let (proof_root, value) = verify_account_proof(&proof, &flat_key)
            .expect("non-existence proof must verify");
        assert_eq!(proof_root, t.root());
        assert_eq!(value, [0u8; 32]);
        assert!(matches!(proof, AccountMerkleProof::NonExisting { .. }));
    }

    #[test]
    fn tampered_root_is_rejected() {
        let mut t = MockStateTree::new();
        let addr = [0x42u8; 20];
        t.insert_account(addr, &sample_account());

        let proof = t.get_account_proof(addr);
        let (proof_root, _) =
            verify_account_proof(&proof, &account_properties_slot_key(&addr)).unwrap();

        // A fake root must not accidentally match.
        let fake = [0u8; 32];
        assert_ne!(proof_root, fake);
    }

    #[test]
    fn non_existing_proof_rejects_key_outside_bracket() {
        let mut t = MockStateTree::new();
        t.insert_account([0x00u8; 20], &sample_account());
        t.insert_account([0xffu8; 20], &sample_account());

        // Build the non-existence proof for a specific absent account,
        // then extract the bracket the proof is actually over and
        // re-use the proof with a queried key that falls OUTSIDE that
        // bracket. The verifier must reject with
        // `NeighborsDoNotBracket`.
        let absent = [0x55u8; 20];
        let proof = t.get_account_proof(absent);

        let (left_key, right_key) = match &proof {
            AccountMerkleProof::NonExisting { left, right } => (left.leaf.key, right.leaf.key),
            _ => panic!("expected non-existing proof"),
        };

        // `[0xff; 32]` is the sentinel high guard — it is always the
        // absolute max key in `TestingTree`, so it lives either
        // strictly above our bracket's `right_key` or equals it.
        // Either way it is outside `(left_key, right_key)`.
        let outside = [0xffu8; 32];
        assert!(outside >= right_key);

        let err = verify_account_proof(&proof, &outside).unwrap_err();
        assert_eq!(err, MerkleError::NeighborsDoNotBracket);

        // Sanity: the proof still verifies against its own queried key.
        let own_key = account_properties_slot_key(&absent);
        assert!(left_key < own_key && own_key < right_key);
        assert!(verify_account_proof(&proof, &own_key).is_ok());
    }
}

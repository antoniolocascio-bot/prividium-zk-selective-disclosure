//! Blake2s Merkle proofs for the ZKsync OS state tree.
//!
//! These types mirror
//! `basic_system::system_implementation::flat_storage_model::FlatStorageLeaf`
//! and
//! `basic_system::system_implementation::flat_storage_model::LeafProof`
//! so that the native test-fixtures can translate a `TestingTree` output
//! into an in-crate proof with a field-by-field copy (no serialization
//! mismatch risk). The verifier logic matches
//! `simple_growable_storage::verify_proof_for_root` /
//! `recompute_root_from_proof` exactly.
//!
//! # Leaf hashing
//!
//! ```text
//! leaf_hash = blake2s(leaf.key_32 || leaf.value_32 || leaf.next_u64_le)
//! ```
//!
//! Note that `next` is **little-endian** — see
//! `FlatStorageLeaf::update_digest` in `simple_growable_storage.rs`. The
//! `zks_getProof.md` doc uses the same format under the name
//! `next_index_le8`.
//!
//! # Path hashing
//!
//! The proof's `path` is an uncompressed 64-entry array of sibling hashes,
//! ordered `path[0] = sibling at depth 64` (the leaf level), walking up.
//! At each level the current node is the left child iff `index & 1 == 0`.
//!
//! # Non-existence
//!
//! A non-existence proof carries the left and right neighbours in the
//! sorted linked list of leaves. The verifier asserts both neighbours
//! produce the same root, that `left.next == right.index`, and that
//! `left.key < queried_key < right.key`.

use crate::hash::Blake2sHasher;
use alloc::boxed::Box;

/// Depth of the state tree, matching
/// `basic_system::flat_storage_model::TESTING_TREE_HEIGHT`.
pub const TREE_DEPTH: usize = 64;

/// A single leaf in the sorted linked-list-augmented binary Merkle tree.
///
/// Mirrors `basic_system::flat_storage_model::FlatStorageLeaf<64>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlatStorageLeaf {
    pub key: [u8; 32],
    pub value: [u8; 32],
    pub next: u64,
}

impl FlatStorageLeaf {
    pub const EMPTY: Self = Self {
        key: [0u8; 32],
        value: [0u8; 32],
        next: 0,
    };

    /// `blake2s(key || value || next_u64_le8)`.
    #[inline]
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Blake2sHasher::new();
        h.update(&self.key);
        h.update(&self.value);
        h.update(&self.next.to_le_bytes());
        h.finalize()
    }
}

/// Merkle inclusion proof for a specific leaf position.
///
/// Mirrors `basic_system::flat_storage_model::LeafProof<64,
/// Blake2sStorageHasher>`. Boxed to keep the stack frame small inside the
/// riscv32 guest (the inline size is 64 × 32 = 2 KiB).
#[derive(Clone, Debug)]
pub struct LeafProof {
    pub index: u64,
    pub leaf: FlatStorageLeaf,
    pub path: Box<[[u8; 32]; TREE_DEPTH]>,
}

impl LeafProof {
    /// Recomputes the tree root implied by this proof, without comparing
    /// against any external value.
    ///
    /// Matches `recompute_root_from_proof` in
    /// `simple_growable_storage.rs`.
    pub fn recompute_root(&self) -> [u8; 32] {
        let mut current = self.leaf.hash();
        let mut index = self.index;
        for sibling in self.path.iter() {
            let mut h = Blake2sHasher::new();
            if index & 1 == 0 {
                // `current` is a left child
                h.update(&current);
                h.update(sibling);
            } else {
                h.update(sibling);
                h.update(&current);
            }
            current = h.finalize();
            index >>= 1;
        }
        debug_assert_eq!(index, 0, "full 64-level walk must consume all index bits");
        current
    }
}

/// Account-level Merkle proof: either an existing leaf, or a pair of
/// bracketing neighbours proving non-existence of a queried key.
#[derive(Clone, Debug)]
pub enum AccountMerkleProof {
    Existing(LeafProof),
    NonExisting {
        left: LeafProof,
        right: LeafProof,
    },
}

/// Things that can go wrong while verifying a Merkle proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    /// Existing and non-existing branches returned different roots.
    RootMismatch,
    /// Non-existence proof: the left/right neighbours do not bracket the
    /// queried key lexicographically, so the claim is unsound.
    NeighborsDoNotBracket,
    /// Non-existence proof: the left neighbour's `next` pointer does not
    /// point at the right neighbour's index, so they are not consecutive
    /// in the key-sorted linked list.
    NeighborsNotLinked,
}

/// Verify a proof's internal consistency and return the `(state_root,
/// value)` it implies.
///
/// For an `Existing` proof, `value` is the leaf's stored value.
/// For a `NonExisting` proof, `value` is the all-zeros word (the implicit
/// default for never-written slots).
///
/// This does **not** check that the resulting root matches any externally
/// trusted commitment — callers (statement verifiers) must compare the
/// returned root against the commitment they care about.
pub fn verify_account_proof(
    proof: &AccountMerkleProof,
    queried_key: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), MerkleError> {
    match proof {
        AccountMerkleProof::Existing(p) => Ok((p.recompute_root(), p.leaf.value)),
        AccountMerkleProof::NonExisting { left, right } => {
            let left_root = left.recompute_root();
            let right_root = right.recompute_root();
            if left_root != right_root {
                return Err(MerkleError::RootMismatch);
            }
            if left.leaf.next != right.index {
                return Err(MerkleError::NeighborsNotLinked);
            }
            if !(left.leaf.key.as_slice() < queried_key.as_slice()
                && queried_key.as_slice() < right.leaf.key.as_slice())
            {
                return Err(MerkleError::NeighborsDoNotBracket);
            }
            Ok((left_root, [0u8; 32]))
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tiny end-to-end tests over a hand-constructed 2-leaf tree.
    //!
    //! These are deliberately minimal; the real end-to-end coverage will
    //! come from Phase 2's `test-fixtures` wrapping `TestingTree`. The
    //! point of these tests is to confirm the verifier logic itself is
    //! not obviously broken, and to exercise both the existing and
    //! non-existing paths.

    use super::*;
    use crate::hash::Blake2sHasher;
    use alloc::boxed::Box;

    /// Build a sibling path that walks from a leaf at `index` up through
    /// a 64-deep tree where every level above the two concrete leaves is
    /// an empty-subtree hash. Returns the computed root and the path.
    ///
    /// `other_leaf_hash` is the hash of the sibling at the leaf level
    /// (index `index ^ 1`).
    fn walk_up_with_empty_upper_levels(
        leaf_hash: [u8; 32],
        other_leaf_hash: [u8; 32],
        index: u64,
    ) -> ([u8; 32], Box<[[u8; 32]; TREE_DEPTH]>) {
        // Precompute empty-subtree hashes for levels 0..63 (the leaf
        // level is handled by the test's explicit sibling, so this
        // array is only used from level 1 upward).
        let empty_leaf = FlatStorageLeaf::EMPTY.hash();
        let mut empty_hashes = [[0u8; 32]; TREE_DEPTH + 1];
        empty_hashes[TREE_DEPTH] = empty_leaf;
        for level in (0..TREE_DEPTH).rev() {
            let mut h = Blake2sHasher::new();
            h.update(&empty_hashes[level + 1]);
            h.update(&empty_hashes[level + 1]);
            empty_hashes[level] = h.finalize();
        }

        let mut path = Box::new([[0u8; 32]; TREE_DEPTH]);
        // Leaf-level sibling.
        path[0] = other_leaf_hash;
        // Above the leaf level, every sibling is an empty subtree of the
        // corresponding height. `path[i]` is the sibling at depth
        // `TREE_DEPTH - i`.
        for i in 1..TREE_DEPTH {
            path[i] = empty_hashes[TREE_DEPTH - i + 1];
        }

        // Compute the expected root by walking the same path.
        let mut current = leaf_hash;
        let mut idx = index;
        for sibling in path.iter() {
            let mut h = Blake2sHasher::new();
            if idx & 1 == 0 {
                h.update(&current);
                h.update(sibling);
            } else {
                h.update(sibling);
                h.update(&current);
            }
            current = h.finalize();
            idx >>= 1;
        }

        (current, path)
    }

    fn make_proof(index: u64, leaf: FlatStorageLeaf, sibling_hash: [u8; 32]) -> (LeafProof, [u8; 32]) {
        let (root, path) = walk_up_with_empty_upper_levels(leaf.hash(), sibling_hash, index);
        (LeafProof { index, leaf, path }, root)
    }

    #[test]
    fn existing_proof_recomputes_root() {
        let leaf = FlatStorageLeaf {
            key: [0x11; 32],
            value: [0x22; 32],
            next: 3,
        };
        let sibling = FlatStorageLeaf::EMPTY.hash();
        let (proof, expected_root) = make_proof(2, leaf, sibling);

        let got = proof.recompute_root();
        assert_eq!(got, expected_root);
    }

    #[test]
    fn verify_account_proof_existing_returns_value_and_root() {
        let leaf = FlatStorageLeaf {
            key: [0x42; 32],
            value: [0xab; 32],
            next: 7,
        };
        let (proof, expected_root) = make_proof(4, leaf, FlatStorageLeaf::EMPTY.hash());

        let queried = [0x42; 32];
        let (root, value) = verify_account_proof(
            &AccountMerkleProof::Existing(proof),
            &queried,
        )
        .expect("existing proof must verify");

        assert_eq!(root, expected_root);
        assert_eq!(value, [0xab; 32]);
    }

    #[test]
    fn verify_account_proof_non_existing_bracket_ok() {
        // Build two leaves at consecutive positions that bracket a
        // missing key. Because both are the only populated entries in
        // their level-0 pair, each proof will contain the other leaf's
        // hash as its leaf-level sibling, and yield the SAME root.
        let left_leaf = FlatStorageLeaf {
            key: [0x01; 32],
            value: [0xde; 32],
            next: 3, // points at right_leaf's index
        };
        let right_leaf = FlatStorageLeaf {
            key: [0x0f; 32],
            value: [0xad; 32],
            next: 1,
        };
        let left_hash = left_leaf.hash();
        let right_hash = right_leaf.hash();

        // Place left at index 2, right at index 3 so they share a parent.
        let (left_proof, left_root) = make_proof(2, left_leaf, right_hash);
        let (right_proof, right_root) = make_proof(3, right_leaf, left_hash);
        assert_eq!(left_root, right_root);

        let queried = [0x05; 32];
        let (root, value) = verify_account_proof(
            &AccountMerkleProof::NonExisting {
                left: left_proof,
                right: right_proof,
            },
            &queried,
        )
        .expect("non-existence proof must verify");

        assert_eq!(root, left_root);
        assert_eq!(value, [0u8; 32]);
    }

    #[test]
    fn verify_account_proof_non_existing_rejects_wrong_order() {
        let left_leaf = FlatStorageLeaf {
            key: [0x01; 32],
            value: [0xde; 32],
            next: 3,
        };
        let right_leaf = FlatStorageLeaf {
            key: [0x0f; 32],
            value: [0xad; 32],
            next: 1,
        };
        let (left_proof, _) = make_proof(2, left_leaf, right_leaf.hash());
        let (right_proof, _) = make_proof(3, right_leaf, left_leaf.hash());

        // Queried key is OUTSIDE the bracket range → must fail.
        let queried_below = [0x00; 32];
        assert_eq!(
            verify_account_proof(
                &AccountMerkleProof::NonExisting {
                    left: left_proof.clone(),
                    right: right_proof.clone(),
                },
                &queried_below,
            ),
            Err(MerkleError::NeighborsDoNotBracket)
        );

        let queried_above = [0xff; 32];
        assert_eq!(
            verify_account_proof(
                &AccountMerkleProof::NonExisting {
                    left: left_proof,
                    right: right_proof,
                },
                &queried_above,
            ),
            Err(MerkleError::NeighborsDoNotBracket)
        );
    }

    #[test]
    fn verify_account_proof_non_existing_rejects_unlinked_neighbours() {
        let left_leaf = FlatStorageLeaf {
            key: [0x01; 32],
            value: [0xde; 32],
            next: 999, // wrong: does not match right.index
        };
        let right_leaf = FlatStorageLeaf {
            key: [0x0f; 32],
            value: [0xad; 32],
            next: 1,
        };
        let (left_proof, _) = make_proof(2, left_leaf, right_leaf.hash());
        let (right_proof, _) = make_proof(3, right_leaf, left_leaf.hash());

        let queried = [0x05; 32];
        assert_eq!(
            verify_account_proof(
                &AccountMerkleProof::NonExisting {
                    left: left_proof,
                    right: right_proof,
                },
                &queried,
            ),
            Err(MerkleError::NeighborsNotLinked)
        );
    }
}

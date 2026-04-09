//! Thin wrappers around Blake2s-256 and Keccak-256.
//!
//! We re-export RustCrypto's `blake2::Blake2s256` and `sha3::Keccak256` under
//! a small convenience surface so callers do not have to think about
//! `Digest` trait imports or output sizes. Both are used in `no_std` mode
//! with default features disabled; this compiles cleanly for both the
//! native host target and `riscv32im-risc0-zkvm-elf`.
//!
//! A future `accelerated` feature flag can swap these for the prover-
//! accelerated primitives in `airbender-sdk` when the guest cycle budget
//! becomes a concern. The API is chosen to make that swap mechanical.

// Both `blake2` and `sha3` re-export the same `digest::Digest` trait, so a
// single import in scope is enough to call `.new() / .update() / .finalize()`
// on either hasher type.
use blake2::Digest as _;

/// Size of a Blake2s-256 digest in bytes.
pub const BLAKE2S_OUTPUT: usize = 32;
/// Size of a Keccak-256 digest in bytes.
pub const KECCAK256_OUTPUT: usize = 32;

/// Compute the Blake2s-256 hash of `input` in one shot.
#[inline]
pub fn blake2s_256(input: &[u8]) -> [u8; BLAKE2S_OUTPUT] {
    let mut hasher = blake2::Blake2s256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Compute the Keccak-256 hash of `input` in one shot.
#[inline]
pub fn keccak256(input: &[u8]) -> [u8; KECCAK256_OUTPUT] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Incremental Blake2s-256 hasher.
#[derive(Clone, Default)]
pub struct Blake2sHasher {
    inner: blake2::Blake2s256,
}

impl Blake2sHasher {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: blake2::Blake2s256::new(),
        }
    }

    #[inline]
    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.inner.update(bytes);
        self
    }

    #[inline]
    pub fn finalize(self) -> [u8; BLAKE2S_OUTPUT] {
        self.inner.finalize().into()
    }
}

/// Incremental Keccak-256 hasher.
#[derive(Clone, Default)]
pub struct Keccak256Hasher {
    inner: sha3::Keccak256,
}

impl Keccak256Hasher {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: sha3::Keccak256::new(),
        }
    }

    #[inline]
    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.inner.update(bytes);
        self
    }

    #[inline]
    pub fn finalize(self) -> [u8; KECCAK256_OUTPUT] {
        self.inner.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known Blake2s-256 digest of the empty input.
    /// From the Blake2 reference vectors.
    const BLAKE2S_EMPTY: [u8; 32] = [
        0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a,
        0x7c, 0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0,
        0xee, 0xf9,
    ];

    /// Known Keccak-256 digest of the empty input (not the same as
    /// SHA3-256!). This is the ZKsync OS `TransactionsRollingKeccakHasher`
    /// initial state.
    const KECCAK256_EMPTY: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];

    #[test]
    fn blake2s_matches_empty_vector() {
        assert_eq!(blake2s_256(&[]), BLAKE2S_EMPTY);
    }

    #[test]
    fn keccak256_matches_empty_vector() {
        assert_eq!(keccak256(&[]), KECCAK256_EMPTY);
    }

    #[test]
    fn incremental_matches_one_shot_blake2s() {
        let input = b"prividium-zk-selective-disclosure";
        let one_shot = blake2s_256(input);
        let mut h = Blake2sHasher::new();
        h.update(&input[..10]);
        h.update(&input[10..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn incremental_matches_one_shot_keccak256() {
        let input = b"prividium-zk-selective-disclosure";
        let one_shot = keccak256(input);
        let mut h = Keccak256Hasher::new();
        h.update(&input[..3]);
        h.update(&input[3..30]);
        h.update(&input[30..]);
        assert_eq!(h.finalize(), one_shot);
    }
}

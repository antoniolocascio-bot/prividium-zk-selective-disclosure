//! ZKsync OS `AccountProperties` encoding and Blake2s hash.
//!
//! Mirrors
//! `basic_system::system_implementation::flat_storage_model::AccountProperties`
//! and its 124-byte big-endian `encoding()` / `compute_hash()` in
//! `account_cache_entry.rs`.
//!
//! Layout (all big-endian):
//!
//! ```text
//! offset len   field
//!      0   8   versioning_data            u64
//!      8   8   nonce                      u64
//!     16  32   balance                    U256
//!     48  32   bytecode_hash              [u8; 32]
//!     80   4   unpadded_code_len          u32
//!     84   4   artifacts_len              u32
//!     88  32   observable_bytecode_hash   [u8; 32]
//!    120   4   observable_bytecode_len    u32
//!    124
//! ```
//!
//! The tree value for an account's properties slot is
//! `blake2s(encoding())` — note that ZKsync OS implements this as a
//! **streamed** blake2s over individual fields, which is equivalent to
//! `blake2s(encoding())` because the byte sequence is identical. We use
//! the one-shot form here since we only ever need to produce the hash
//! from an already-decoded struct.

use crate::hash::blake2s_256;

/// Serialized size of an `AccountProperties` blob.
pub const ENCODED_SIZE: usize = 124;

/// Decoded account properties. Field names and types mirror
/// `basic_system::flat_storage_model::AccountProperties`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountProperties {
    /// Packed versioning metadata (deployment status, EE version, etc.).
    /// Treated as an opaque `u64` on our side — we do not interpret it.
    pub versioning_data: u64,
    pub nonce: u64,
    /// Base-token balance as a big-endian 32-byte U256.
    pub balance: [u8; 32],
    pub bytecode_hash: [u8; 32],
    pub unpadded_code_len: u32,
    pub artifacts_len: u32,
    pub observable_bytecode_hash: [u8; 32],
    pub observable_bytecode_len: u32,
}

impl AccountProperties {
    pub const TRIVIAL: Self = Self {
        versioning_data: 0,
        nonce: 0,
        balance: [0u8; 32],
        bytecode_hash: [0u8; 32],
        unpadded_code_len: 0,
        artifacts_len: 0,
        observable_bytecode_hash: [0u8; 32],
        observable_bytecode_len: 0,
    };

    /// Encode into the canonical 124-byte big-endian layout.
    pub fn encode(&self) -> [u8; ENCODED_SIZE] {
        let mut out = [0u8; ENCODED_SIZE];
        out[0..8].copy_from_slice(&self.versioning_data.to_be_bytes());
        out[8..16].copy_from_slice(&self.nonce.to_be_bytes());
        out[16..48].copy_from_slice(&self.balance);
        out[48..80].copy_from_slice(&self.bytecode_hash);
        out[80..84].copy_from_slice(&self.unpadded_code_len.to_be_bytes());
        out[84..88].copy_from_slice(&self.artifacts_len.to_be_bytes());
        out[88..120].copy_from_slice(&self.observable_bytecode_hash);
        out[120..124].copy_from_slice(&self.observable_bytecode_len.to_be_bytes());
        out
    }

    /// Decode from the canonical 124-byte layout.
    ///
    /// The input is a fixed-size `[u8; 124]`, so this function is
    /// infallible and panic-free: every sub-slice indexed below is a
    /// constant range that always fits. The intermediate copies into
    /// stack buffers exist specifically to avoid `try_into().unwrap()`
    /// and keep the function free of any `unwrap` / `expect` call
    /// that could be reached from an adversarial witness byte stream.
    pub fn decode(bytes: &[u8; ENCODED_SIZE]) -> Self {
        let mut u64_buf = [0u8; 8];

        u64_buf.copy_from_slice(&bytes[0..8]);
        let versioning_data = u64::from_be_bytes(u64_buf);

        u64_buf.copy_from_slice(&bytes[8..16]);
        let nonce = u64::from_be_bytes(u64_buf);

        let mut balance = [0u8; 32];
        balance.copy_from_slice(&bytes[16..48]);

        let mut bytecode_hash = [0u8; 32];
        bytecode_hash.copy_from_slice(&bytes[48..80]);

        let mut u32_buf = [0u8; 4];
        u32_buf.copy_from_slice(&bytes[80..84]);
        let unpadded_code_len = u32::from_be_bytes(u32_buf);

        u32_buf.copy_from_slice(&bytes[84..88]);
        let artifacts_len = u32::from_be_bytes(u32_buf);

        let mut observable_bytecode_hash = [0u8; 32];
        observable_bytecode_hash.copy_from_slice(&bytes[88..120]);

        u32_buf.copy_from_slice(&bytes[120..124]);
        let observable_bytecode_len = u32::from_be_bytes(u32_buf);

        Self {
            versioning_data,
            nonce,
            balance,
            bytecode_hash,
            unpadded_code_len,
            artifacts_len,
            observable_bytecode_hash,
            observable_bytecode_len,
        }
    }

    /// `blake2s(encoding())` — the value stored in the tree at the
    /// account's properties slot.
    #[inline]
    pub fn compute_hash(&self) -> [u8; 32] {
        blake2s_256(&self.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Blake2sHasher;

    #[test]
    fn encoded_size_is_124_bytes() {
        assert_eq!(ENCODED_SIZE, 124);
        assert_eq!(AccountProperties::TRIVIAL.encode().len(), 124);
    }

    #[test]
    fn encode_decode_round_trip() {
        let props = AccountProperties {
            versioning_data: 0x01_23_45_67_89_ab_cd_ef,
            nonce: 42,
            balance: {
                let mut b = [0u8; 32];
                // 0xdeadbeef as a BE U256
                b[28] = 0xde;
                b[29] = 0xad;
                b[30] = 0xbe;
                b[31] = 0xef;
                b
            },
            bytecode_hash: [0xaa; 32],
            unpadded_code_len: 1234,
            artifacts_len: 5678,
            observable_bytecode_hash: [0xbb; 32],
            observable_bytecode_len: 9999,
        };

        let encoded = props.encode();
        let decoded = AccountProperties::decode(&encoded);
        assert_eq!(decoded, props);
    }

    #[test]
    fn trivial_encoding_is_all_zeros() {
        assert_eq!(AccountProperties::TRIVIAL.encode(), [0u8; ENCODED_SIZE]);
    }

    #[test]
    fn compute_hash_matches_streamed_form() {
        // ZKsync OS computes the hash by streaming each field through
        // Blake2s in order. Because the encoded byte layout is the same
        // concatenation, the streamed form and the one-shot form must
        // yield identical digests. This test locks that property in
        // place and guards against any future drift in the streaming
        // order.
        let props = AccountProperties {
            versioning_data: 0x11_22_33_44_55_66_77_88,
            nonce: 7,
            balance: [0x42; 32],
            bytecode_hash: [0x13; 32],
            unpadded_code_len: 100,
            artifacts_len: 200,
            observable_bytecode_hash: [0x37; 32],
            observable_bytecode_len: 300,
        };

        let one_shot = props.compute_hash();

        let mut h = Blake2sHasher::new();
        h.update(&props.versioning_data.to_be_bytes());
        h.update(&props.nonce.to_be_bytes());
        h.update(&props.balance);
        h.update(&props.bytecode_hash);
        h.update(&props.unpadded_code_len.to_be_bytes());
        h.update(&props.artifacts_len.to_be_bytes());
        h.update(&props.observable_bytecode_hash);
        h.update(&props.observable_bytecode_len.to_be_bytes());
        let streamed = h.finalize();

        assert_eq!(one_shot, streamed);
    }

    /// Fixed vector: encode a concrete struct and freeze the byte layout.
    /// If this fails, the wire format has changed — bump carefully and
    /// cross-check against `basic_system` `AccountProperties::encoding`.
    #[test]
    fn encoding_layout_is_stable() {
        let props = AccountProperties {
            versioning_data: 0x0102030405060708,
            nonce: 0x1112131415161718,
            balance: [0x20u8; 32],
            bytecode_hash: [0x30u8; 32],
            unpadded_code_len: 0x41_42_43_44,
            artifacts_len: 0x51_52_53_54,
            observable_bytecode_hash: [0x60u8; 32],
            observable_bytecode_len: 0x71_72_73_74,
        };
        let encoded = props.encode();

        assert_eq!(&encoded[0..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(&encoded[8..16], &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
        assert_eq!(&encoded[16..48], &[0x20u8; 32]);
        assert_eq!(&encoded[48..80], &[0x30u8; 32]);
        assert_eq!(&encoded[80..84], &[0x41, 0x42, 0x43, 0x44]);
        assert_eq!(&encoded[84..88], &[0x51, 0x52, 0x53, 0x54]);
        assert_eq!(&encoded[88..120], &[0x60u8; 32]);
        assert_eq!(&encoded[120..124], &[0x71, 0x72, 0x73, 0x74]);
    }
}

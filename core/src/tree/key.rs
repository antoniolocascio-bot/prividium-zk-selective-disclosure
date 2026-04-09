//! Flat storage key derivation for the ZKsync OS state tree.
//!
//! Mirrors
//! [`zk_ee::common_structs::derive_flat_storage_key`](../../../../zksync-os/zk_ee/src/common_structs/warm_storage_key.rs)
//! and
//! [`basic_system::flat_storage_model::address_into_special_storage_key`](../../../../zksync-os/basic_system/src/system_implementation/flat_storage_model/mod.rs).
//!
//! Every slot in the tree is keyed by
//! `flat_key = blake2s(addr_padded_32_be || storage_key_32)`
//! where `addr_padded_32_be` is the 20-byte big-endian address left-padded
//! to 32 bytes with zeros. This is the exact derivation described in
//! `zksync-os-server/docs/src/design/zks_getProof.md` § Key derivation.
//!
//! Account properties (balance, observable bytecode hash, …) live under a
//! special synthetic address:
//!
//! - `address = ACCOUNT_PROPERTIES_STORAGE_ADDRESS = 0x8003` (as a B160);
//! - `storage_key = user_address_left_padded_to_32_bytes`.
//!
//! So the flat key for an account's properties slot is
//! `blake2s(pad32(0x8003) || pad32(user_address))` — the two helpers below
//! build exactly that.

use crate::hash::blake2s_256;

/// Left-pad a 20-byte address to 32 bytes with zeros.
#[inline]
pub const fn pad_address(address: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 20 {
        out[12 + i] = address[i];
        i += 1;
    }
    out
}

/// The synthetic "account properties" address (`0x8003`) used by ZKsync OS
/// to store the Blake2s hash of every account's properties blob, pre-padded
/// to the 32-byte form used by `flat_storage_key`.
pub const ACCOUNT_PROPERTIES_STORAGE_ADDRESS_PADDED: [u8; 32] = {
    let mut out = [0u8; 32];
    out[30] = 0x80;
    out[31] = 0x03;
    out
};

/// Compute the flat Merkle-tree key for an arbitrary
/// `(address_padded_32_be, storage_key)` pair:
///
/// `blake2s(address_padded_32_be || storage_key)`.
#[inline]
pub fn flat_storage_key(
    address_padded_32_be: &[u8; 32],
    storage_key: &[u8; 32],
) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(address_padded_32_be);
    buf[32..].copy_from_slice(storage_key);
    blake2s_256(&buf)
}

/// Compute the flat Merkle-tree key under which an account's
/// `blake2s(AccountProperties)` hash is stored.
#[inline]
pub fn account_properties_slot_key(user_address: &[u8; 20]) -> [u8; 32] {
    let padded_user_address = pad_address(*user_address);
    flat_storage_key(
        &ACCOUNT_PROPERTIES_STORAGE_ADDRESS_PADDED,
        &padded_user_address,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Blake2sHasher;

    #[test]
    fn pad_address_matches_manual_layout() {
        let addr = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let padded = pad_address(addr);
        assert_eq!(&padded[..12], &[0u8; 12]);
        assert_eq!(&padded[12..], &addr);
    }

    #[test]
    fn account_properties_address_is_0x8003() {
        // Mirrors `B160::from_limbs([0x8003, 0, 0])` encoded as 20 BE
        // bytes, then left-padded to 32.
        assert_eq!(&ACCOUNT_PROPERTIES_STORAGE_ADDRESS_PADDED[..30], &[0u8; 30]);
        assert_eq!(ACCOUNT_PROPERTIES_STORAGE_ADDRESS_PADDED[30], 0x80);
        assert_eq!(ACCOUNT_PROPERTIES_STORAGE_ADDRESS_PADDED[31], 0x03);
    }

    #[test]
    fn flat_storage_key_is_blake2s_of_concatenation() {
        // Cross-check: the streaming form must match the one-shot blake2s
        // over the 64-byte concatenation.
        let addr = [0x42u8; 32];
        let key = [0xcdu8; 32];
        let one_shot = flat_storage_key(&addr, &key);

        let mut h = Blake2sHasher::new();
        h.update(&addr);
        h.update(&key);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn account_slot_key_structure() {
        let user = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        ];
        let got = account_properties_slot_key(&user);

        // Equivalent manual construction.
        let mut expected_input = [0u8; 64];
        expected_input[30] = 0x80;
        expected_input[31] = 0x03;
        expected_input[32 + 12..].copy_from_slice(&user);
        let expected = blake2s_256(&expected_input);

        assert_eq!(got, expected);
    }
}

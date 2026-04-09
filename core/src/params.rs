//! Fixed-layout public-parameter structs for each statement.
//!
//! Every statement has a byte-layout that is hashed into the public-input
//! commitment (see [`crate::pub_input`]) and that is also the shape the
//! verifier must know to reconstruct that commitment from a proof bundle.
//!
//! The layouts here are canonical — both the guest and any native tools
//! that build a bundle must use the exact same concatenation order and
//! endianness.
//!
//! Layouts (all big-endian where applicable):
//!
//! | Statement                 | `statement_id` | Params bytes                                              | Total |
//! |---------------------------|----------------|-----------------------------------------------------------|-------|
//! | `BalanceOf`               | `1`            | `address[20] \|\| balance[32]`                            | 52    |
//! | `ObservableBytecodeHash`  | `2`            | `address[20] \|\| hash[32]`                               | 52    |
//! | `TxInclusion`             | `3`            | `block_number_be8[8] \|\| tx_hash[32]`                    | 40    |

/// Public parameters for the `balance_of` statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceOfParams {
    pub address: [u8; 20],
    /// Base-token balance as a big-endian 32-byte U256.
    pub balance: [u8; 32],
}

impl BalanceOfParams {
    pub const ENCODED_SIZE: usize = 20 + 32;

    pub fn to_bytes(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut out = [0u8; Self::ENCODED_SIZE];
        out[..20].copy_from_slice(&self.address);
        out[20..].copy_from_slice(&self.balance);
        out
    }
}

/// Public parameters for the `observable_bytecode_hash` statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservableBytecodeHashParams {
    pub address: [u8; 20],
    pub observable_bytecode_hash: [u8; 32],
}

impl ObservableBytecodeHashParams {
    pub const ENCODED_SIZE: usize = 20 + 32;

    pub fn to_bytes(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut out = [0u8; Self::ENCODED_SIZE];
        out[..20].copy_from_slice(&self.address);
        out[20..].copy_from_slice(&self.observable_bytecode_hash);
        out
    }
}

/// Public parameters for the `tx_inclusion` statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxInclusionParams {
    pub block_number: u64,
    pub tx_hash: [u8; 32],
}

impl TxInclusionParams {
    pub const ENCODED_SIZE: usize = 8 + 32;

    pub fn to_bytes(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut out = [0u8; Self::ENCODED_SIZE];
        out[..8].copy_from_slice(&self.block_number.to_be_bytes());
        out[8..].copy_from_slice(&self.tx_hash);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_of_layout() {
        let addr = [0x01u8; 20];
        let mut balance = [0u8; 32];
        balance[31] = 0x42;
        let params = BalanceOfParams { address: addr, balance };

        let bytes = params.to_bytes();
        assert_eq!(bytes.len(), 52);
        assert_eq!(&bytes[..20], &addr);
        assert_eq!(&bytes[20..], &balance);
    }

    #[test]
    fn observable_bytecode_hash_layout() {
        let addr = [0x02u8; 20];
        let hash = [0x33u8; 32];
        let params = ObservableBytecodeHashParams {
            address: addr,
            observable_bytecode_hash: hash,
        };

        let bytes = params.to_bytes();
        assert_eq!(bytes.len(), 52);
        assert_eq!(&bytes[..20], &addr);
        assert_eq!(&bytes[20..], &hash);
    }

    #[test]
    fn tx_inclusion_layout() {
        let block_number = 0x1122_3344_5566_7788u64;
        let tx_hash = [0x77u8; 32];
        let params = TxInclusionParams { block_number, tx_hash };

        let bytes = params.to_bytes();
        assert_eq!(bytes.len(), 40);
        assert_eq!(
            &bytes[..8],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        );
        assert_eq!(&bytes[8..], &tx_hash);
    }
}

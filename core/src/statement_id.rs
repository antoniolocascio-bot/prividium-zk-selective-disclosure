//! Statement identifiers.
//!
//! A single `u32` tag that disambiguates which statement a proof is
//! attesting to. The tag is the first thing mixed into the public-input
//! commitment (see [`crate::pub_input`]) so that two statements with
//! coincidentally identical trailing bytes cannot collide.
//!
//! Adding a new statement is an additive change: assign the next free
//! discriminant and extend the dispatcher. Existing proofs and their
//! verification keys remain valid.

/// Errors returned when decoding a statement id from the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementIdError {
    /// The wire tag does not correspond to a known statement.
    Unknown(u32),
}

/// Which statement a proof is about.
///
/// Discriminants are part of the wire format (they are hashed into the
/// public input) and must never be renumbered.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatementId {
    /// `balance_of(batch_number, l1_commitment, address, balance)`
    BalanceOf = 1,
    /// `observable_bytecode_hash(batch_number, l1_commitment, address, hash)`
    ObservableBytecodeHash = 2,
    /// `tx_inclusion(batch_number, l1_commitment, block_number, tx_hash)`
    TxInclusion = 3,
}

impl StatementId {
    /// Wire-format encoding of the tag.
    #[inline]
    pub const fn to_u32(self) -> u32 {
        self as u32
    }
}

impl TryFrom<u32> for StatementId {
    type Error = StatementIdError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::BalanceOf),
            2 => Ok(Self::ObservableBytecodeHash),
            3 => Ok(Self::TxInclusion),
            other => Err(StatementIdError::Unknown(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_ids() {
        for id in [
            StatementId::BalanceOf,
            StatementId::ObservableBytecodeHash,
            StatementId::TxInclusion,
        ] {
            assert_eq!(StatementId::try_from(id.to_u32()).unwrap(), id);
        }
    }

    #[test]
    fn discriminants_are_stable() {
        // These are part of the wire format. If any of these asserts
        // fire, we are about to break every already-issued proof.
        assert_eq!(StatementId::BalanceOf as u32, 1);
        assert_eq!(StatementId::ObservableBytecodeHash as u32, 2);
        assert_eq!(StatementId::TxInclusion as u32, 3);
    }

    #[test]
    fn unknown_id_is_rejected() {
        assert_eq!(
            StatementId::try_from(0),
            Err(StatementIdError::Unknown(0))
        );
        assert_eq!(
            StatementId::try_from(4),
            Err(StatementIdError::Unknown(4))
        );
        assert_eq!(
            StatementId::try_from(u32::MAX),
            Err(StatementIdError::Unknown(u32::MAX))
        );
    }
}

//! Trait for things that can build a [`crate::prover::ProveRequest`]
//! from a high-level [`DisclosureRequest`].
//!
//! This is the library's one explicit seam between "fetch state from
//! somewhere" and "run a prover". Implementations are expected to be:
//!
//! - **trusted for the purpose of data fetching but not for soundness**:
//!   the guest re-derives the L1 commitment from the raw witness
//!   bytes and rejects anything that doesn't hash back to the public
//!   `l1_commitment`. A lying `WitnessSource` can only cause the
//!   prover to fail, not to produce a forged proof.
//! - **async**: the canonical impl is `rpc_l2::RpcWitnessSource`
//!   which does a few JSON-RPC round trips per request. Mock impls
//!   that don't need any awaits can trivially implement the async
//!   methods by returning `ready(...)`.
//!
//! The trait uses `async fn in trait` (native, no `async_trait`
//! crate). We require `Sync + Send` for implementations so they can
//! be used across tokio tasks in the future.

use crate::disclosure_request::DisclosureRequest;
use crate::prover::ProveRequest;
use std::error::Error;

/// Something that can translate a [`DisclosureRequest`] into a fully
/// prepared [`ProveRequest`] ready for the airbender prover.
///
/// The trait method is async because the canonical implementation
/// talks to remote RPC endpoints. See [`crate::rpc_l2`] for the real
/// implementation and [`mock::MockWitnessSource`] for a test-only
/// one that serves precomputed scenarios.
pub trait WitnessSource: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    // NOTE: we deliberately use the `impl Future + Send` form here
    // rather than `async fn` in the trait. `async fn` in a public
    // trait leaves the returned `Future` with an unspecified auto-
    // trait set, which would break our `prove_from_source` helper
    // that needs the future to be `Send` so it can be blocked on
    // from a multithreaded runtime. Implementors are free to use
    // `async fn` in their `impl` block; the `Send` bound is auto-
    // detected from the impl body by the compiler.
    fn fetch(
        &self,
        request: DisclosureRequest,
    ) -> impl std::future::Future<Output = Result<ProveRequest, Self::Error>> + Send;
}

/// Test-only witness sources.
pub mod mock {
    use super::*;
    use crate::prover::ProveRequest;
    use alloy::primitives::{Address, B256};
    use prividium_sd_core::statement_id::StatementId;
    use std::collections::HashMap;

    /// Key for the mock witness-source map. We key by
    /// `(statement_id, batch_number, discriminator)` where
    /// `discriminator` is the hash of the statement-specific fields
    /// that identify the request (address for the two account
    /// statements, tx hash for tx_inclusion).
    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    struct MockKey {
        statement_id: u32,
        batch_number: u64,
        discriminator: [u8; 32],
    }

    /// In-memory [`WitnessSource`] backed by a `(request →
    /// ProveRequest)` map. Used by integration tests to feed
    /// precomputed scenarios into the prover without any RPC.
    #[derive(Default)]
    pub struct MockWitnessSource {
        map: HashMap<MockKey, ProveRequest>,
    }

    /// Errors returned by [`MockWitnessSource`].
    #[derive(Debug, thiserror::Error)]
    pub enum MockWitnessError {
        #[error("no scenario registered for this disclosure request")]
        NotFound,
    }

    impl MockWitnessSource {
        pub fn new() -> Self {
            Self::default()
        }

        /// Register a prebuilt [`ProveRequest`] for a specific
        /// disclosure request. On lookup, the mock just returns a
        /// clone.
        pub fn insert(&mut self, request: &DisclosureRequest, prove_request: ProveRequest) {
            self.map.insert(Self::key(request), prove_request);
        }

        pub fn with_request(
            mut self,
            request: &DisclosureRequest,
            prove_request: ProveRequest,
        ) -> Self {
            self.insert(request, prove_request);
            self
        }

        fn key(request: &DisclosureRequest) -> MockKey {
            match request {
                DisclosureRequest::BalanceOf {
                    batch_number,
                    address,
                } => MockKey {
                    statement_id: StatementId::BalanceOf as u32,
                    batch_number: *batch_number,
                    discriminator: address_to_discriminator(*address),
                },
                DisclosureRequest::ObservableBytecodeHash {
                    batch_number,
                    address,
                } => MockKey {
                    statement_id: StatementId::ObservableBytecodeHash as u32,
                    batch_number: *batch_number,
                    discriminator: address_to_discriminator(*address),
                },
                DisclosureRequest::TxInclusion {
                    batch_number,
                    tx_hash,
                } => MockKey {
                    statement_id: StatementId::TxInclusion as u32,
                    batch_number: *batch_number,
                    discriminator: b256_to_discriminator(*tx_hash),
                },
            }
        }
    }

    fn address_to_discriminator(address: Address) -> [u8; 32] {
        let mut d = [0u8; 32];
        d[12..].copy_from_slice(address.as_slice());
        d
    }

    fn b256_to_discriminator(hash: B256) -> [u8; 32] {
        hash.0
    }

    impl WitnessSource for MockWitnessSource {
        type Error = MockWitnessError;

        async fn fetch(
            &self,
            request: DisclosureRequest,
        ) -> Result<ProveRequest, Self::Error> {
            self.map
                .get(&Self::key(&request))
                .cloned()
                .ok_or(MockWitnessError::NotFound)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use prividium_sd_core::statement_id::StatementId;

        fn dummy_prove_request(statement: StatementId, batch: u64) -> ProveRequest {
            ProveRequest {
                statement_id: statement,
                batch_number: batch,
                l1_commitment: [0u8; 32],
                params_bytes: Vec::new(),
                witness_bytes: Vec::new(),
            }
        }

        #[tokio::test]
        async fn mock_returns_registered_prove_request() {
            let addr = Address::from([0x11; 20]);
            let request = DisclosureRequest::BalanceOf {
                batch_number: 42,
                address: addr,
            };
            let src = MockWitnessSource::new().with_request(
                &request,
                dummy_prove_request(StatementId::BalanceOf, 42),
            );

            let fetched = src.fetch(request).await.unwrap();
            assert_eq!(fetched.statement_id, StatementId::BalanceOf);
            assert_eq!(fetched.batch_number, 42);
        }

        #[tokio::test]
        async fn mock_returns_not_found_for_unknown_request() {
            let src = MockWitnessSource::new();
            let request = DisclosureRequest::BalanceOf {
                batch_number: 1,
                address: Address::ZERO,
            };
            assert!(matches!(
                src.fetch(request).await,
                Err(MockWitnessError::NotFound)
            ));
        }
    }
}

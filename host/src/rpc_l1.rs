//! L1 RPC-backed implementation of [`L1Source`].
//!
//! Calls `diamondProxy.storedBatchHash(uint64)` on the configured L1
//! Ethereum node (typically `anvil` in local dev or a real Ethereum
//! RPC in production) and returns the on-chain batch hash. This is
//! the verifier's only trust root — if the L1 returns a wrong hash,
//! the rest of the verification pipeline either fails or binds to the
//! wrong batch.
//!
//! Auto-discovery of the diamond proxy via `Bridgehub::getZKChain`
//! (as the server's `verify-storage-proof` tool does) is out of scope
//! for now; the caller must supply the proxy address directly. That
//! keeps this module focused on one RPC call.

use crate::l1_source::L1Source;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use alloy::sol_types::SolCall;

sol! {
    #[allow(missing_docs)]
    interface IZKChain {
        function storedBatchHash(uint256 _batchNumber) external view returns (bytes32);
    }
}

/// L1 source that queries a live Ethereum JSON-RPC endpoint.
///
/// Internally blocks on a tokio runtime per call. The caller can
/// either provide their own runtime handle or let the source create a
/// small current-thread runtime on first use.
pub struct RpcL1Source {
    provider: DynProvider,
    diamond_proxy: Address,
    runtime: tokio::runtime::Runtime,
}

/// Errors returned by [`RpcL1Source`].
#[derive(Debug, thiserror::Error)]
pub enum RpcL1SourceError {
    #[error("failed to build tokio runtime: {0}")]
    Runtime(#[from] std::io::Error),
    #[error("failed to parse L1 RPC URL: {0}")]
    Url(String),
    #[error("L1 RPC call failed: {0}")]
    Rpc(#[from] alloy::transports::TransportError),
    #[error("storedBatchHash ABI decode failed: {0}")]
    Decode(#[from] alloy::sol_types::Error),
    #[error("storedBatchHash returned zero for batch {0} — batch not committed to L1 yet")]
    BatchNotCommitted(u64),
}

impl RpcL1Source {
    /// Build an L1 source from an RPC URL and the diamond proxy
    /// address. The URL may be HTTP(S) or any other transport alloy
    /// supports out of the box.
    pub fn new(l1_rpc_url: &str, diamond_proxy: Address) -> Result<Self, RpcL1SourceError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let url = l1_rpc_url
            .parse()
            .map_err(|e: url::ParseError| RpcL1SourceError::Url(e.to_string()))?;
        let provider = ProviderBuilder::new().connect_http(url).erased();
        Ok(Self {
            provider,
            diamond_proxy,
            runtime,
        })
    }

    /// Async variant of [`L1Source::stored_batch_hash`] for callers
    /// that already have a tokio runtime and want to avoid the
    /// block-on dance.
    pub async fn stored_batch_hash_async(
        &self,
        batch_number: u64,
    ) -> Result<[u8; 32], RpcL1SourceError> {
        let call = IZKChain::storedBatchHashCall {
            _batchNumber: U256::from(batch_number),
        };
        let tx = TransactionRequest::default()
            .to(self.diamond_proxy)
            .input(alloy::primitives::Bytes::from(call.abi_encode()).into());
        let result = self.provider.call(tx).await?;
        let hash: B256 =
            <IZKChain::storedBatchHashCall as SolCall>::abi_decode_returns(&result)?;
        if hash == B256::ZERO {
            return Err(RpcL1SourceError::BatchNotCommitted(batch_number));
        }
        Ok(hash.0)
    }
}

impl L1Source for RpcL1Source {
    type Error = RpcL1SourceError;

    fn stored_batch_hash(&self, batch_number: u64) -> Result<[u8; 32], Self::Error> {
        self.runtime
            .block_on(self.stored_batch_hash_async(batch_number))
    }
}

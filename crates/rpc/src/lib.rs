use crate::prelude::*;
use async_trait::async_trait;
use futures::TryFutureExt;
use near_jsonrpc_client::{
    methods::{
        self, light_client_proof::RpcLightClientExecutionProofResponse,
        validators::RpcValidatorResponse,
    },
    JsonRpcClient,
};
use near_primitives::{
    types::{validator_stake::ValidatorStake, ValidatorStakeV1},
    views::{validator_stake_view::ValidatorStakeView, LightClientBlockView},
};
use std::fmt::{Display, Formatter};

pub mod prelude;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum Network {
    Mainnet,
    #[default]
    Testnet,
    Localnet,
}

impl Network {
    pub fn to_endpoint(&self) -> &str {
        const MAINNET_RPC_ENDPOINT: &str = "https://rpc.mainnet.near.org";
        const TESTNET_RPC_ENDPOINT: &str = "https://rpc.testnet.near.org";
        match self {
            Self::Mainnet => MAINNET_RPC_ENDPOINT,
            Self::Testnet => TESTNET_RPC_ENDPOINT,
            _ => "http://`localhost:3030",
        }
    }
    pub fn archive_endpoint(&self) -> &str {
        const MAINNET_RPC_ARCHIVE_ENDPOINT: &str = "https://archival-rpc.mainnet.near.org";
        const TESTNET_RPC_ARCHIVE_ENDPOINT: &str = "https://archival-rpc.testnet.near.org";
        match self {
            Self::Mainnet => MAINNET_RPC_ARCHIVE_ENDPOINT,
            Self::Testnet => TESTNET_RPC_ARCHIVE_ENDPOINT,
            _ => "http://`localhost:3030",
        }
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            _ => "localnet",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone)]
pub struct NearRpcClient {
    client: JsonRpcClient,
    archive: JsonRpcClient,
}

impl std::fmt::Debug for NearRpcClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NearRpcClient").finish()
    }
}

impl NearRpcClient {
    pub fn new(network: Network) -> Self {
        let client = JsonRpcClient::connect(network.to_endpoint());
        let archive = JsonRpcClient::connect(network.archive_endpoint());

        NearRpcClient { client, archive }
    }
}

#[async_trait]
pub trait LightClientRpc {
    async fn fetch_latest_header(
        &self,
        latest_verified: &CryptoHash,
    ) -> Result<Option<LightClientBlockView>>;
    async fn fetch_light_client_proof(
        &self,
        req: GetProof,
        latest_verified: CryptoHash,
    ) -> Result<RpcLightClientExecutionProofResponse>;
    async fn fetch_epoch_bps(&self, epoch_id: &CryptoHash) -> Result<Vec<ValidatorStakeView>>;
}

#[async_trait]
impl LightClientRpc for NearRpcClient {
    async fn fetch_latest_header(
        &self,
        latest_verified: &CryptoHash,
    ) -> Result<Option<LightClientBlockView>> {
        let req = methods::next_light_client_block::RpcLightClientNextBlockRequest {
            last_block_hash: *latest_verified,
        };
        log::debug!("requesting next block: {:?}", req);
        self.client
            .call(&req)
            .or_else(|e| {
                debug!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .map_err(|e| anyhow::format_err!("{:?}", e))
    }

    async fn fetch_light_client_proof(
        &self,
        req: GetProof,
        latest_verified: CryptoHash,
    ) -> Result<RpcLightClientExecutionProofResponse> {
        let req = methods::light_client_proof::RpcLightClientExecutionProofRequest {
            id: req,
            light_client_head: latest_verified,
        };
        self.client
            .call(&req)
            .or_else(|e| {
                debug!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .map_err(|e| anyhow::format_err!("{:?}:{}", req.id, e))
    }

    async fn fetch_epoch_bps(&self, epoch_id: &CryptoHash) -> Result<Vec<ValidatorStakeView>> {
        let req = methods::validators::RpcValidatorRequest {
            epoch_reference: near_primitives::types::EpochReference::EpochId(
                near_primitives::types::EpochId(*epoch_id),
            ),
        };
        self.client
            .call(&req)
            .or_else(|e| {
                debug!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .map(|x| x.current_proposals)
            .map_err(|e| anyhow::format_err!("{:?}:{}", epoch_id, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {}
}

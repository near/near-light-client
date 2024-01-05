use anyhow::Result;
use futures::TryFutureExt;
use log::debug;
use near_jsonrpc_client::{
    methods::{self, light_client_proof::RpcLightClientExecutionProofResponse},
    JsonRpcClient,
};
use near_primitives::views::LightClientBlockView;
use near_primitives_core::hash::CryptoHash;
use serde::Deserialize;
use std::fmt::{Display, Formatter};

use super::message::GetProof;

// TODO: retry, failover rpcs

#[derive(Debug, Clone, Deserialize, Default)]
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

    pub async fn fetch_latest_header(
        &self,
        latest_verified: &CryptoHash,
    ) -> Option<LightClientBlockView> {
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
            .map_err(|e| {
                log::error!("Error fetching latest header: {:?}", e);
                e
            })
            .ok()?
    }

    pub async fn fetch_light_client_proof(
        &self,
        req: GetProof,
        latest_verified: CryptoHash,
    ) -> Result<RpcLightClientExecutionProofResponse> {
        let req = methods::light_client_proof::RpcLightClientExecutionProofRequest {
            id: req.0,
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
}

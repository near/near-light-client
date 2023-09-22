use futures::TryFutureExt;
use log::debug;
use near_jsonrpc_client::{
    methods::{self, light_client_proof::RpcLightClientExecutionProofResponse},
    JsonRpcClient,
};
use near_primitives::{types::TransactionOrReceiptId, views::LightClientBlockView};
use near_primitives_core::{hash::CryptoHash, types::AccountId};
use serde::Deserialize;
use std::fmt::{Display, Formatter};

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
        self.client
            .call(&req)
            .or_else(|e| {
                debug!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .ok()?
    }

    pub async fn fetch_light_client_tx_proof(
        &self,
        transaction_id: CryptoHash,
        sender_id: AccountId,
        latest_verified: CryptoHash,
    ) -> Option<RpcLightClientExecutionProofResponse> {
        let req = methods::light_client_proof::RpcLightClientExecutionProofRequest {
            id: TransactionOrReceiptId::Transaction {
                transaction_hash: transaction_id,
                sender_id,
            },
            light_client_head: latest_verified,
        };
        self.client
            .call(&req)
            .or_else(|e| {
                debug!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .ok()
    }
    pub async fn fetch_light_client_receipt_proof(
        &self,
        receipt_id: CryptoHash,
        receiver_id: AccountId,
        latest_verified: CryptoHash,
    ) -> Option<RpcLightClientExecutionProofResponse> {
        let req = methods::light_client_proof::RpcLightClientExecutionProofRequest {
            id: TransactionOrReceiptId::Receipt {
                receipt_id,
                receiver_id,
            },
            light_client_head: latest_verified,
        };
        self.client
            .call(&req)
            .or_else(|e| {
                debug!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .ok()
    }
}

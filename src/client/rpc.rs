use near_jsonrpc_client::{
    methods::{self, light_client_proof::RpcLightClientExecutionProofResponse},
    JsonRpcClient,
};
use near_primitives::{types::TransactionOrReceiptId, views::LightClientBlockView};
use near_primitives_core::{hash::CryptoHash, types::AccountId};
use serde::Deserialize;
use std::fmt::Formatter;

#[derive(Debug, Clone, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
    Localnet,
}

impl Network {
    fn to_endpoint(&self) -> &str {
        const MAINNET_RPC_ENDPOINT: &str = "https://rpc.mainnet.near.org";
        const MAINNET_RPC_ARCHIVE_ENDPOINT: &str = "https://archival-rpc.mainnet.near.org";
        const TESTNET_RPC_ENDPOINT: &str = "https://rpc.testnet.near.org";
        const TESTNET_RPC_ARCHIVE_ENDPOINT: &str = "https://archival-rpc.testnet.near.org";
        match self {
            Self::Mainnet => MAINNET_RPC_ARCHIVE_ENDPOINT,
            Self::Testnet => TESTNET_RPC_ARCHIVE_ENDPOINT,
            _ => "http://`localhost:3030",
        }
    }
}

#[derive(Clone)]
pub struct NearRpcClient {
    client: JsonRpcClient,
}

impl std::fmt::Debug for NearRpcClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NearRpcClient").finish()
    }
}

impl NearRpcClient {
    pub fn new(network: Network) -> Self {
        let client = JsonRpcClient::connect(network.to_endpoint());

        NearRpcClient { client }
    }

    pub async fn fetch_latest_header(
        &self,
        latest_verified: &CryptoHash,
    ) -> Option<LightClientBlockView> {
        self.client
            .call(
                methods::next_light_client_block::RpcLightClientNextBlockRequest {
                    last_block_hash: *latest_verified,
                },
            )
            .await
            .ok()?
    }

    pub async fn fetch_light_client_tx_proof(
        &self,
        transaction_id: CryptoHash,
        sender_id: AccountId,
        latest_verified: CryptoHash,
    ) -> Option<RpcLightClientExecutionProofResponse> {
        self.client
            .call(
                methods::light_client_proof::RpcLightClientExecutionProofRequest {
                    id: TransactionOrReceiptId::Transaction {
                        transaction_hash: transaction_id,
                        sender_id,
                    },
                    light_client_head: latest_verified,
                },
            )
            .await
            .ok()
    }
    pub async fn fetch_light_client_receipt_proof(
        &self,
        receipt_id: CryptoHash,
        receiver_id: AccountId,
        latest_verified: CryptoHash,
    ) -> Option<RpcLightClientExecutionProofResponse> {
        self.client
            .call(
                methods::light_client_proof::RpcLightClientExecutionProofRequest {
                    id: TransactionOrReceiptId::Receipt {
                        receipt_id,
                        receiver_id,
                    },
                    light_client_head: latest_verified,
                },
            )
            .await
            .ok()
    }
}

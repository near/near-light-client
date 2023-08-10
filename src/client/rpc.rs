use std::{fmt::Formatter, str::FromStr};

use near_jsonrpc_client::{
    methods::{self, light_client_proof::RpcLightClientExecutionProofResponse},
    JsonRpcClient,
};
use near_primitives::{types::TransactionOrReceiptId, views::LightClientBlockView};
use near_primitives_core::{hash::CryptoHash, types::AccountId};
use serde::Deserialize;

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
        Some(
            self.client
                .call(
                    methods::light_client_proof::RpcLightClientExecutionProofRequest {
                        id: TransactionOrReceiptId::Transaction {
                            transaction_hash: transaction_id,
                            sender_id: sender_id,
                        },
                        light_client_head: latest_verified,
                    },
                )
                .await
                .ok()?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_response() -> JsonRpcResult {
        serde_json::from_reader(std::fs::File::open("fixtures/1_current_epoch.json").unwrap())
            .unwrap()
    }
    fn get_response2() -> JsonRpcResult {
        serde_json::from_reader(std::fs::File::open("fixtures/rpc_result.json").unwrap()).unwrap()
    }

    #[test]
    fn sanity_test_response() {
        let res = get_response();
        assert_eq!(res.jsonrpc, "2.0");
        if let NearRpcResult::NextBlock(..) = res.result {
            assert!(true);
        } else {
            panic!("Unexpected response from near rpc")
        }
    }

    #[test]
    fn sanity_test_response2() {
        let res = get_response2();
        assert_eq!(res.jsonrpc, "2.0");
        if let NearRpcResult::NextBlock(..) = res.result {
            assert!(true);
        } else {
            panic!("Unexpected response from near rpc")
        }
    }

    #[test]
    fn test_serialize_next_block_correctly() {
        let request = NearRpcRequestParams::NextBlock {
            last_block_hash: "2rs9o3B6nAQ3pEfVcBQdLnBqZrfpVuZJeKC8FpTshhua".to_string(),
        };
        let json_rpc: JsonRpcRequest = request.into();
        assert_eq!(json_rpc.jsonrpc, "2.0");
        assert_eq!(json_rpc.method, "next_light_client_block");
        let req = serde_json::to_string(&json_rpc).unwrap();
        log::info!("{}", req);
        assert_eq!(
            req,
            r#"{"jsonrpc":"2.0","method":"next_light_client_block","params":{"last_block_hash":"2rs9o3B6nAQ3pEfVcBQdLnBqZrfpVuZJeKC8FpTshhua"},"id":"pagoda-near-light-client"}"#
        )
    }

    #[test]
    fn test_serialize_tx_proof_correctly() {
        let request = NearRpcRequestParams::ExperimentalLightClientProof {
            kind: "receipt".to_string(),
            params: LightClientProofParams::Receipt {
                receipt_id: "5TGZe4jsuUGx9A65HNuEMkb3J4vW6Wo2pxDbyzYFrDeC".to_string(),
                receiver_id: "7496c752687339dbd12c68535011a8994cfa727f3263bdb65fc879063c4b365a"
                    .to_string(),
            },
            light_client_head: "14gQvvYkY2MrKxikmSoEF5nmgwnrQZqU6kmfxdaSSS88".to_string(),
        };
        let json_rpc: JsonRpcRequest = request.into();
        assert_eq!(json_rpc.jsonrpc, "2.0");
        assert_eq!(json_rpc.method, "EXPERIMENTAL_light_client_proof");
        let req = serde_json::to_string(&json_rpc).unwrap();
        log::info!("{}", req);
        assert_eq!(
            req,
            r#"{"jsonrpc":"2.0","method":"EXPERIMENTAL_light_client_proof","params":{"type":"receipt","receipt_id":"5TGZe4jsuUGx9A65HNuEMkb3J4vW6Wo2pxDbyzYFrDeC","receiver_id":"7496c752687339dbd12c68535011a8994cfa727f3263bdb65fc879063c4b365a","light_client_head":"14gQvvYkY2MrKxikmSoEF5nmgwnrQZqU6kmfxdaSSS88"},"id":"pagoda-near-light-client"}"#
        )
    }
}

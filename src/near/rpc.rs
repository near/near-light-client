use std::fmt::Formatter;

use near_primitives::views::LightClientBlockView;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    RequestBuilder,
};
use serde::{Deserialize, Serialize};

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[derive(Deserialize, Serialize, Default)]
pub struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: NearRpcRequestParams,
    id: String,
}

impl JsonRpcRequest {
    pub fn new(method: String, params: NearRpcRequestParams) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method,
            params,
            id: "pagoda-near-light-client".to_string(),
        }
    }
}

impl From<NearRpcRequestParams> for JsonRpcRequest {
    fn from(params: NearRpcRequestParams) -> Self {
        let method = params.get_method_name();
        Self::new(method, params)
    }
}

#[derive(Deserialize, Serialize)]
pub struct JsonRpcResult {
    id: String,
    jsonrpc: String,
    pub result: NearRpcResult,
}

impl From<NearRpcResult> for JsonRpcResult {
    fn from(result: NearRpcResult) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result,
            id: "bbb".to_string(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum NearRpcResult {
    NextBlock(LightClientBlockView),
    ExperimentalLightClientProof(LightClientBlockView),
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum LightClientProofParams {
    Transaction {
        transaction_hash: String,
        sender_id: String,
    },
    Receipt {
        receipt_id: String,
        receiver_id: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum NearRpcRequestParams {
    NextBlock {
        last_block_hash: String,
    },
    ExperimentalLightClientProof {
        #[serde(rename = "type")]
        kind: String,
        #[serde(flatten)]
        params: LightClientProofParams,
        light_client_head: String,
    },
}
impl Default for NearRpcRequestParams {
    fn default() -> Self {
        Self::NextBlock {
            last_block_hash: "".to_string(),
        }
    }
}

impl NearRpcRequestParams {
    fn get_method_name(&self) -> String {
        match self {
            NearRpcRequestParams::NextBlock { .. } => "next_light_client_block".to_string(),
            NearRpcRequestParams::ExperimentalLightClientProof { .. } => {
                "EXPERIMENTAL_light_client_proof".to_string()
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
    Localnet,
}

impl Network {
    fn to_endpoint(&self, params: &NearRpcRequestParams) -> &str {
        const MAINNET_RPC_ENDPOINT: &str = "https://rpc.mainnet.near.org";
        const MAINNET_RPC_ARCHIVE_ENDPOINT: &str = "https://archival-rpc.mainnet.near.org";
        const TESTNET_RPC_ENDPOINT: &str = "https://rpc.testnet.near.org";
        const TESTNET_RPC_ARCHIVE_ENDPOINT: &str = "https://archival-rpc.testnet.near.org";

        match (self, params) {
            (Network::Mainnet, NearRpcRequestParams::NextBlock { .. }) => MAINNET_RPC_ENDPOINT,
            (Network::Mainnet, NearRpcRequestParams::ExperimentalLightClientProof { .. }) => {
                MAINNET_RPC_ARCHIVE_ENDPOINT
            }
            (Network::Testnet, NearRpcRequestParams::NextBlock { .. }) => TESTNET_RPC_ENDPOINT,
            (Network::Testnet, NearRpcRequestParams::ExperimentalLightClientProof { .. }) => {
                TESTNET_RPC_ARCHIVE_ENDPOINT
            }
            _ => "http://localhost:3030",
        }
    }
}

pub struct NearRpcClient {
    network: Network,
    client: reqwest::Client,
}

impl std::fmt::Debug for NearRpcClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NearRpcClient").finish()
    }
}

impl NearRpcClient {
    pub fn new(network: Network) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .user_agent(APP_USER_AGENT)
            .default_headers(headers)
            .gzip(true)
            .brotli(true)
            .deflate(true)
            .build()
            .unwrap();

        NearRpcClient { network, client }
    }

    pub fn build_request(&self, body: &JsonRpcRequest) -> RequestBuilder {
        self.client
            .post(self.network.to_endpoint(&body.params))
            .json(body)
    }

    pub async fn fetch_latest_header(&self, latest_verified: &str) -> Option<LightClientBlockView> {
        let request = self.build_request(
            &NearRpcRequestParams::NextBlock {
                last_block_hash: latest_verified.to_string(),
            }
            .into(),
        );

        let response = request
            .send()
            .await // Sending the request out by the host
            .map_err(|e| {
                log::info!("{:?}", e);
            })
            .unwrap();

        if !response.status().is_success() {
            log::info!(
                "Unexpected http request status code: {:?}",
                response.status()
            );
        }
        // log::info!("Response: {:#?}", response.text().await.unwrap());

        let res: Option<JsonRpcResult> = response.json().await.ok()?;
        if let Some(NearRpcResult::NextBlock(block)) = res.map(|r| r.result) {
            Some(block)
        } else {
            None
        }
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

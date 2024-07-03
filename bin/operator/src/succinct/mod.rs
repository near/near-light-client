use std::{str::FromStr, time::Duration};

use alloy::{
    primitives::*,
    providers::{network::Ethereum, Provider as ProviderExt, RootProvider},
    sol_types::SolValue,
    transports::http::Http,
};
use anyhow::{ensure, Context};
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use near_light_client_rpc::prelude::{CryptoHash, Itertools};
pub use near_light_clientx::plonky2x::backend::prover::ProofId;
use near_light_clientx::{
    config::bps_from_network,
    plonky2x::{
        backend::{
            circuit::DefaultParameters,
            function::{BytesRequestData, ProofRequest, ProofRequestBase},
        },
        utils::hex,
    },
};
use reqwest::{
    header::{self, HeaderMap, HeaderValue},
    Url,
};
use reqwest_middleware::ClientWithMiddleware;
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use serde::Deserialize;
use succinct_client::{request::SuccinctClient as SuccinctClientExt, utils::get_gateway_address};
use tracing::{debug, info, trace};
use types::TransactionOrReceiptIdPrimitive;

use self::types::{Circuit, Deployment, NearX::NearXInstance, NearXClient, ProofResponse};
use crate::{config, succinct::types::ProofRequestResponse, types::NearX::TransactionOrReceiptId};

pub mod types;

type Provider = RootProvider<Ethereum, Http<reqwest::Client>>;

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Config {
    /// The succinct platform api key
    pub api_key: String,
    /// The succinct platform rpc
    #[serde(default = "default_rpc")]
    pub rpc_url: String,
    /// ETH rpc where the contract is deployed
    pub eth_rpc_url: String,
    /// Address of the eth contract
    pub contract_address: Address,
    /// The version we are targeting
    pub version: String,
    /// Github organisation_id id for the proof platform
    #[serde(default = "default_organisation")]
    pub organisation_id: String,
    /// Github project id
    #[serde(default = "default_project")]
    pub project_id: String,
    /// Max retries when waiting for a request
    #[serde(default = "default_max_retries")]
    pub client_max_retries: u32,
    /// Request timeout from the platform, in seconds
    #[serde(default = "default_timeout")]
    pub client_timeout: u64,
}

fn default_rpc() -> String {
    "https://alpha.succinct.xyz/api".into()
}

fn default_organisation() -> String {
    "near".into()
}

fn default_project() -> String {
    "near-light-client".into()
}

fn default_max_retries() -> u32 {
    3
}

fn default_timeout() -> u64 {
    30
}

pub struct Client {
    config: Config,
    inner: ClientWithMiddleware,
    contract: NearXInstance<Ethereum, Http<reqwest::Client>, Provider>,
    ext: SuccinctClientExt,
    genesis: CryptoHash,
    releases: Vec<Deployment>,
    verify_amt: usize,
}

impl Client {
    pub async fn new(config: &config::Config) -> anyhow::Result<Self> {
        info!("starting succinct client");
        info!("rpc: {}", config.succinct.rpc_url);
        info!("contract address: {}", config.succinct.contract_address);
        info!("eth rpc: {}", config.succinct.eth_rpc_url);

        ensure!(
            config.succinct.contract_address != Address::ZERO,
            "invalid contract address",
        );
        let (contract, chain_id) = Self::init_contract_client(&config.succinct).await?;

        let inner = Self::init_inner_client(&config.succinct).await?;

        // TODO[Feature]: introduce override if succinct wont relay the proof, call to a
        // hosted prover who will prove, relay and unbrick
        let succinct_client = SuccinctClientExt::new(
            config.succinct.rpc_url.clone(),
            config.succinct.api_key.clone(),
            false,
            false,
        );

        let mut s = Self {
            inner,
            contract,
            config: config.succinct.clone(),
            ext: succinct_client,
            genesis: config.protocol.genesis,
            releases: Default::default(),
            verify_amt: bps_from_network(&config.rpc.network),
        };
        s.releases = s.fetch_releases(&chain_id).await?;
        ensure!(!s.releases.is_empty(), "no releases found");

        Ok(s)
    }

    async fn init_contract_client(config: &Config) -> anyhow::Result<(NearXClient, u32)> {
        debug!("initializing contract client");

        let url = Url::from_str(&config.eth_rpc_url).with_context(|| "invalid rpc url")?;
        let inner = Provider::new_http(url);
        let chain_id = inner
            .get_chain_id()
            .await
            .with_context(|| "failed to get chain id")?;
        let contract = NearXInstance::new(config.contract_address, inner);
        debug!("chain id: {}", chain_id);

        Ok((contract, chain_id.to()))
    }

    async fn init_inner_client(config: &Config) -> anyhow::Result<ClientWithMiddleware> {
        let mut headers = HeaderMap::new();
        let mut auth = HeaderValue::from_str(&format!("Bearer {}", config.api_key))?;
        auth.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth);

        let inner = reqwest::ClientBuilder::default()
            .timeout(std::time::Duration::from_secs(config.client_timeout)) // Long timeout to avoid spamming api
            .default_headers(headers)
            .build()?;

        let retry_policy =
            ExponentialBackoff::builder().build_with_max_retries(config.client_max_retries);
        let client = reqwest_middleware::ClientBuilder::new(inner)
            .with(Cache(HttpCache {
                mode: CacheMode::Default,
                manager: CACacheManager::default(),
                options: HttpCacheOptions::default(),
            }))
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Ok(client)
    }

    #[tracing::instrument(skip(self))]
    async fn fetch_releases(&self, chain_id: &u32) -> anyhow::Result<Vec<Deployment>> {
        debug!(
            "filtering releases for {chain_id} and version {}",
            self.config.version
        );
        Ok(Self::extract_release_details(
            self.fetch_deployments().await?,
            chain_id,
            &self.config.version,
        ))
        .inspect(|r| debug!("releases: {:?}", r))
    }

    fn extract_release_details(
        deployments: Vec<Deployment>,
        chain_id: &u32,
        version: &str,
    ) -> Vec<Deployment> {
        let gateway: Option<Address> = get_gateway_address(*chain_id).and_then(|a| a.parse().ok());
        deployments
            .into_iter()
            .filter(|d| d.release_info.release.name.contains(version))
            .filter(|d| d.chain_id == *chain_id)
            .filter_map(|mut d| {
                if d.gateway == Address::ZERO {
                    gateway.map(|a| {
                        d.gateway = a;
                        d
                    })
                } else {
                    debug!("matched deployment: {:#?}", d);
                    Some(d)
                }
            })
            .collect_vec()
    }

    fn build_proof_request_bytes(
        &self,
        release_id: &str,
        data: BytesRequestData,
    ) -> ProofRequest<DefaultParameters, 2> {
        trace!(
            "building proof request for {:?} with data {:?}",
            release_id,
            hex!(&data.input)
        );
        ProofRequest::<DefaultParameters, 2>::Bytes(ProofRequestBase {
            release_id: release_id.to_string(),
            parent_id: None,
            files: None,
            data,
        })
    }

    fn build_sync_request(&self, trusted_header_hash: CryptoHash) -> BytesRequestData {
        debug!("building sync request for {:?}", trusted_header_hash);
        BytesRequestData {
            input: trusted_header_hash.0.to_vec(),
        }
    }

    fn build_verify_request(
        &self,
        trusted_header_hash: CryptoHash,
        ids: Vec<TransactionOrReceiptIdPrimitive>,
    ) -> BytesRequestData {
        debug!("building verify request for {:?}", trusted_header_hash);
        trace!("ids {:?}", ids);
        BytesRequestData {
            // TODO: define this input by abi
            input: [
                trusted_header_hash.0.to_vec(),
                ids.into_iter()
                    .map(TransactionOrReceiptId::from)
                    .collect_vec()
                    .abi_encode_packed(),
            ]
            .concat(),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn fetch_deployments(&self) -> anyhow::Result<Vec<Deployment>> {
        debug!("getting deployments");
        Ok(self
            .inner
            .get(format!(
                "{}/deployments/{}/{}",
                self.config.rpc_url, self.config.organisation_id, self.config.project_id
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .inspect(|d| trace!("fetched deployments: {:?}", d))?)
    }

    #[tracing::instrument(skip(self))]
    async fn request_relayed_proof(
        &self,
        circuit: &Circuit,
        req: BytesRequestData,
    ) -> anyhow::Result<ProofId> {
        ensure!(
            self.config.contract_address.0 != [0u8; 20],
            "no contract address"
        );
        let function_id = circuit.function_id(&self.contract).await?;
        debug!("requesting relayed proof for {:?}", function_id);
        ensure!(
            self.releases
                .iter()
                .any(|d| d.function_id == hex::encode(function_id)),
            "function_id not found in active releases"
        );
        let request_id = self
            .ext
            .submit_request(
                circuit.deployment(&self.releases).chain_id,
                self.config.contract_address.0 .0.into(),
                circuit.with_selector(&req.input).into(),
                function_id.into(),
                req.input.into(),
            )
            .await
            .inspect(|d| debug!("requested relay proof: {:?}", d))?;
        self.wait_for_proof(&request_id).await
    }

    #[tracing::instrument(skip(self))]
    async fn fetch_proofs(&self) -> anyhow::Result<Vec<ProofResponse>> {
        let res: anyhow::Result<_> = Ok(self
            .inner
            .get(format!("{}/proofs", self.config.rpc_url))
            .query(&[
                (
                    "project",
                    format!("{}/{}", self.config.organisation_id, self.config.project_id),
                ),
                ("limit", "10".to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<ProofResponse>>()
            .await?);
        res
    }

    /// Wait for the proof to be submitted to the explorer so we can track them
    /// by their proof id
    #[tracing::instrument(skip(self))]
    pub async fn wait_for_proof(&self, request_id: &str) -> anyhow::Result<ProofId> {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut attempts = 0;
        loop {
            let proofs = self.fetch_proofs().await?;
            if let Some(p) = Self::search_for_request(&proofs, request_id) {
                break Ok(ProofId(p.id));
            }
            attempts += 1;
            if attempts > 10 {
                anyhow::bail!("{request_id} timed out waiting for proof id");
            }
            interval.tick().await;
        }
    }

    fn search_for_request<'p>(
        proofs: &'p [ProofResponse],
        request_id: &str,
    ) -> Option<&'p ProofResponse> {
        proofs
            .iter()
            .find(|p| {
                p.edges.requests.iter().any(|r| {
                    debug!("checking if {:?} matches {:?}", r.id, request_id);
                    r.id == request_id
                })
            })
            .inspect(|p| debug!("found proof {:?} matching request: {:?}", p.id, request_id))
    }

    /// Request a proof to be proven, this doesn't relay the proof to the
    /// contract, useful for users who don't want to relay
    #[tracing::instrument(skip(self))]
    pub async fn request_proof(
        &self,
        circuit: &Circuit,
        req: BytesRequestData,
    ) -> anyhow::Result<ProofId> {
        let release_id = circuit.deployment(&self.releases).release_info.release.id;
        let req = self.build_proof_request_bytes(&release_id, req);

        Ok(self
            .inner
            .post(format!("{}/proof/new", self.config.rpc_url))
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json::<ProofRequestResponse>()
            .await
            .inspect(|d| debug!("requested proof: {:?}", d.proof_id))?
            .proof_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_proof(&self, proof_id: ProofId) -> anyhow::Result<ProofResponse> {
        debug!("fetching proof: {}", proof_id.0);
        Ok(self
            .inner
            .get(format!("{}/proof/{}", self.config.rpc_url, proof_id.0))
            .send()
            .await?
            .error_for_status()?
            .json::<ProofResponse>()
            .await
            .inspect(|d| debug!("fetched proof: {:?}/{:?}", d.id, d.status))?)
    }

    /// Sync the light client
    #[tracing::instrument(skip(self))]
    pub async fn sync(&self, relay: bool) -> anyhow::Result<ProofId> {
        let circuit = Circuit::Sync;
        let req = self.build_sync_request(self.fetch_trusted_header_hash().await?);

        let id = if relay {
            self.request_relayed_proof(&circuit, req).await?
        } else {
            self.request_proof(&circuit, req).await?
        };
        Ok(id)
    }

    /// Verify a set of transactions
    #[tracing::instrument(skip(self))]
    pub async fn verify(
        &self,
        ids: Vec<TransactionOrReceiptIdPrimitive>,
        relay: bool,
    ) -> anyhow::Result<ProofId> {
        trace!("verifying {} ids", ids.len());
        ensure!(
            ids.len() == self.verify_amt,
            format!(
                "wrong number of transactions for verify, expected {}, got {}",
                self.verify_amt,
                ids.len()
            )
        );
        let circuit = Circuit::Verify;
        let req = self.build_verify_request(self.fetch_trusted_header_hash().await?, ids);

        let id = if relay {
            self.request_relayed_proof(&circuit, req).await?
        } else {
            self.request_proof(&circuit, req).await?
        };
        Ok(id)
    }

    /// Fetch the last synced header from the contract
    #[tracing::instrument(skip(self))]
    async fn fetch_trusted_header_hash(&self) -> anyhow::Result<CryptoHash> {
        let mut h = self
            .contract
            .latestHeader()
            .call()
            .await
            .map(|x| *x._0)
            .map(CryptoHash)?;
        debug!("fetched trusted header hash {:?}", h);
        if h == CryptoHash::default() {
            info!("no trusted header found, using checkpoint hash");
            h = self.genesis;
        }
        Ok(h)
    }
}

// FIXME: not using succinct platform anymore, disabling tests
#[cfg(test)]
pub mod tests {
    use alloy::sol_types::SolCall;
    use near_light_client_primitives::config::BaseConfig;
    use serde_json::json;
    use test_utils::{fixture, logger};
    use uuid::Uuid;
    use wiremock::{
        matchers::{body_partial_json, body_string_contains, method, path, query_param_contains},
        Mock, MockServer, ResponseTemplate,
    };

    use self::types::NearX;
    use super::*;

    // const VERIFY_AMT: usize = 64;
    pub struct Stub(Circuit);
    impl Stub {
        pub fn selector(&self) -> String {
            let selector = match self.0 {
                Circuit::Sync => NearX::syncFunctionIdCall::SELECTOR,
                Circuit::Verify => NearX::verifyFunctionIdCall::SELECTOR,
            };
            hex!(selector)
        }

        pub fn proof_id(&self) -> Uuid {
            Uuid::from_str(match self.0 {
                Circuit::Sync => "cde59ba0-a60b-4721-b96c-61401ff28852",
                Circuit::Verify => "582276cc-62f0-4728-9a20-86f260c09874",
            })
            .unwrap()
        }

        pub fn request_id(&self) -> String {
            match self.0 {
                Circuit::Sync => "64bb0a1e-2695-42c8-aee3-9d8c1b17b379",
                Circuit::Verify => "533a983c-ec21-456c-a1dc-79965df9de5f",
            }
            .to_string()
        }

        pub async fn mock(&self, server: &MockServer, releases: &[Deployment]) {
            let d = self.0.deployment(releases);
            // Stub the get function id
            Mock::given(method("POST"))
                .and(path("/"))
                .and(body_string_contains(self.selector()))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",                     "id": 1,
                                    "result": d.function_id
                                })))
                .mount(server)
                .await;

            // Mock for requesting a new platform proof
            Mock::given(method("POST"))
                .and(path("/proof/new"))
                .and(body_string_contains(&d.release_info.release.id))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"proof_id":
     self.proof_id()})))
                .mount(server)
                .await;

            Mock::given(method("POST"))
                .and(path("/request/new"))
                .and(body_string_contains(&d.function_id))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"request_id":
     self.request_id()})),
                )
                .mount(server)
                .await;

            let proof_fixture = match self.0 {
                Circuit::Sync => "sync_proof.json",
                Circuit::Verify => "verify_proof.json",
            };

            Mock::given(method("GET"))
                .and(path(format!("/proof/{}", self.proof_id())))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(fixture::<ProofResponse>(proof_fixture)),
                )
                .mount(server)
                .await;
        }
    }

    impl From<Circuit> for Stub {
        fn from(value: Circuit) -> Self {
            Self(value)
        }
    }

    const CHAIN_ID: u32 = 421614;
    const VERSION: &str = "dev";
    const HEADER_HASH: &str = "0x63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3";

    pub async fn mocks() -> Client {
        logger();

        let deployments = fixture::<Vec<Deployment>>("deployments.json");
        let mut config = crate::config::Config::test_config();
        config.succinct.version = VERSION.to_string();

        let server = MockServer::start().await;
        config.succinct.rpc_url = server.uri();
        config.succinct.eth_rpc_url = server.uri();
        config.succinct.rpc_url = server.uri();

        let releases = Client::extract_release_details(deployments.clone(), &CHAIN_ID, VERSION);

        // Mock for eth_chainId request
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({"method":"eth_chainId"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"jsonrpc":"2.0","id":1,"result":hex!(CHAIN_ID.to_be_bytes())}),
            ))
            .mount(&server)
            .await;

        // Mock for fetching deployments
        Mock::given(method("GET"))
            .and(path("/deployments/near/near-light-client"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&deployments))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/proofs"))
            .and(query_param_contains("project", "near-light-client"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(fixture::<Vec<ProofResponse>>("get_proofs.json")),
            )
            .mount(&server)
            .await;

        // Mock the getTrustedHeaderHash
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains(hex!(
                NearX::latestHeaderCall::SELECTOR
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"jsonrpc":"2.0","id":1,"result":HEADER_HASH})),
            )
            .mount(&server)
            .await;

        Stub(Circuit::Sync).mock(&server, &releases).await;
        Stub(Circuit::Verify).mock(&server, &releases).await;

        Client::new(&config).await.unwrap()
    }

    //     #[tokio::test]
    //     async fn test_can_build_sync() {
    //         let client = mocks().await;
    //         let (header, _, _) = testnet_state();
    //         let hash = header.hash();

    //         let sync_release_id =
    // "1cde66c3-46df-4aab-8409-4cbb97abee1c".to_string();

    //         let req = client.build_sync_request(hash);
    //         assert_eq!(req.input, hash.0.to_vec());

    //         if let ProofRequest::Bytes(full) =
    //             client.build_proof_request_bytes(&sync_release_id,
    // req.clone())         {
    //             println!("{}", serde_json::to_string_pretty(&full).unwrap());

    //             assert_eq!(full.data.input, req.input);
    //             assert_eq!(full.parent_id, None);
    //             assert_eq!(full.files, None);
    //             assert_eq!(full.release_id, sync_release_id);
    //         } else {
    //             panic!("wrong request type");
    //         }
    //     }

    //     #[tokio::test]
    //     async fn test_sync() {
    //         let client = mocks().await;

    //         let s = client.sync(false).await.unwrap();
    //         println!("synced with {:?}", s);
    //     }

    //     #[tokio::test]
    //     async fn test_sync_relay() {
    //         let client = mocks().await;
    //         let s = client.sync(true).await.unwrap();
    //         println!("synced with {:?}", s);
    //     }

    //     #[tokio::test]
    //     async fn test_can_build_verify() {
    //         let (header, _, _) = testnet_state();
    //         let hash = header.hash();

    //         let client = mocks().await;
    //         let verify_release_id =
    // "c35d498e-f283-4b14-a42f-3a35807d3a70".to_string();

    //         let txs =
    // fixture::<Vec<TransactionOrReceiptIdPrimitive>>("ids.json")
    //             .into_iter()
    //             .take(VERIFY_AMT)
    //             .collect_vec();

    //         let req = client.build_verify_request(hash, txs);
    //         pretty_assertions::assert_eq!(req.input[..32], hash.0.to_vec());
    //         // Not using the same as above because of the padding
    //         pretty_assertions::assert_eq!(hex!(&req.input[32..]),
    // "0x009dbbc777884bc0ccc05fc9177bd442e19a9b82608f7ae6c8b81cbadee2320e1c77616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01026d02a778ce47a4a670e343cebf90a67309157b2a3a54079c13b8962908b080686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0024e2d4f8d3394fabea1a8ac255ec3ef9c6e14cc90e8e45c1d185f9a858d484107a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c000a594de1c36eca52f15d9f7d4177515570f3a6966e5ac51da1ce4abb7e496c6a706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007ff581f8517ec58459099a5af2465d5232fdcdd7c4da9c3d42a887bf6bd5457e70726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00311fa837e07749c47b2825d06dd14d3aa6f438e2e1cc69857b737d0104ac080576325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007f454878ba125cc5f380439ee3c3e6510e8d66e7adcb70e59951bcf51c2916d5686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c012c53bcfe871da28decc45c3437f5864568d91af6d990dbc2662f11ce44c18d797a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0156b47c3c713180318844195b0e0e29810c5f099fe19411eaf116d55b3f6d1f96706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0027d1be4cbf7826333bb3a66339314d6b23088907bc03abe8e1f0402f6b8e99fb6f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c006d6c0e7346e597949cf4ef07e57b029426cac6d2a0e80761b07aaa83e5622fe16f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007f4bf0c2de11327648a0b56a170029f349308fc88d64badffaf4b1575a0444056f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00ae58764b2108d1e23de28591a61e52e6fdeb49f0985ab6bf5f332e338db742f877616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c000e7d92ca3c2fbd087783533f3e3c493881189b9e95829763ee2222d5ef50524361737365742d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0010478412784e05112c2ab987ce3d691a1f8d284f5e80d71d573229b6d643563b61737365742d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c009eac5b84d08bbf7716b595fc0d10686ead30355e5b7a8c9305ac02240823513961737365742d6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0124e495308164a0a97925a27e59fadec0c6fc59de23c5ffaef3ff30a2c513d51a686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0133fb9d5f75d87a3cf8eca81ad16c669a686aac61fc514a6cf1159e739618c2e86f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01d6c2a78d92595947756cc38ad2fb077984f691ebbba0d1db03c2cbed071d16ef6f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0133f6198c994c4ca12b360abc226c232f1dd46bef6c5be02c39278b8de8ea04696f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c003d268ee173d6cbe5f0c0efa3833fe6590950938cb7b24b15957587fd0380729375736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c008be60e1ba421b4c0cf104749bd2f322f6d985763053b347bf68c6000908aa693796b616a753261386a6366672e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c002aa060c38662a90fa07a34b800cd3c84360d894dc4bec1c81a7b41d3eb282092706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c006674894d631ca3e373a87b27ea614f16468fa9ddaf401f079d93359f14f29f6e72656c61792e6175726f72612c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00bc656c82f3aed97695b555e49b55e584f960197f092a53ac9bcc3f872125436476325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01a988b23956e4e5ab00dd3d16decdd0714554562ae9fbfae9053acca1a91f37cc75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00883c8876a557200a3b14ad46b0646af75750403ab3cb5ff04ef6a72f4f71b7786175726f72612c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01d916068721ec0d451382e00bebd8f4f713321e3bde850c36463517d6c50115c5706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01bf4b51df07bf9819b996b720eadafc5323ec7a2ad7fc0555190771faaa582d3272656c61792e6175726f72612c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00c1e6131d4648085ea2f1e23ba516e6d03a05c6448c30639b1b082c8650544506686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00956fff9f472d68ff61b7c3e88b678738f5082e44ca40277cb394501a86d8b42177616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c005ef99fadc671ee47c6015c92351d2c172995832ac01ecd1e8b8ceae3722ccc296f7261636c652d322e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c002c0d2c9385d28114166aee120e40fdf5f713f07477e0abd4eb63c7a39da10ac770726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01796847ad9c2cbe2a5006a89dafe3e7838846085f4cd240b97c29d1253a9476c1686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01dcfc4f30c70a7da653f1166a1e4abd70865b0042773485674804591a2d1f001b6f7261636c652d322e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00094532de95f1fa7fa1ae18fdbe8e09bb98c4e3fbb5033a6b5ae990594569b27775736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00c21d9dab00ab7481de442b9d8273dfe151799c66cdf52346a6d9c44c418824306c776a64766c767a666f37392e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c003f185492791bff0827767b40925d34beb5530e55ea6a18cc559a513c96598431706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00af6aecb8c18aeed12c89e10024d7848732c1edc39ac0b47d421c92807d14835c76325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01a25c13eeab4dbb89d8308e148b34c7d52fbb32044c0552da9be982c9b480f22175736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01e99199a0ee36379f8ec381be29fb5429950d7ea2a4e661f9a352d7c2e3f087a6706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0049fcac1e1358c141f432296c655a7f37ad6f799e676b864741e017fa48e1619d6f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c004c55453e68e24a730befcedf4dbf17dcb4522774ebdcdc959bbb8881216f095d6f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00caeed0384fc2e3d27b729993601365870abdeac789239a155b2d2c7c86921ee06f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007366f9850730663c25ad58c7d0b2c92887d5b3521c36627a3f5b0f1cafc23e3d61737365742d6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c008dc95d832842725b8e2dd1752ed1ecbebe0354d7a8b384f6036267433bf8f4f861737365742d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00a2dcd933e13734be2cf545f6f4150a2911041bc4840cd8df25b2e4cfaf84ac4b61737365742d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0045989ff55b321cf17042336002143923eaeb1f7aca1890d06b8661beb5469f4a686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01178da8f0216f3935a7b18792f2f524aaa3e0ce04878be5e88e7374a22588187b6f70657261746f725f6d616e616765722e6f726465726c792e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c016f7c2658d5db3ad5c21b8cd74b67e3cd88583efbb0990c866eada559459f15296f70657261746f722d6d616e616765722e6f726465726c792d71612e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01c743450fa747831ab768ff6b81769b99fdf4dd7a96d77b11b4b134746994b2e06f70657261746f722d6d616e616765722e6f726465726c792d6465762e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00e1d64d332912d157d409dd7b2cd15922d1458c9f89db1a6aaec788722c8c9feb77616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01376545409c923b585549e2775ea44f17cf666c8a96b7f46000470ce8215cc29f686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00bb801a7742b42c0a63572de86a669f4278cbfd2ad83890a78aca8927c5c559a8706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0025effa5cf9769e5e4ee9ea894e96e5fa7f8d2d3e02779afb093c71bfd191c0b175736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00c67d9883f54fdbe34cb4eca5ebea3bd11eb1c643759bfd68312fe30a5538860876325f312e706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00c1f41e50f9b71459d5e937ab570c7ff6eff9c1ca59c58512fb4442de7435160637337576793879366b7872382e75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01fbbdfc15d6cc230ad33560005bd260d319c55b740e974f2670556660bcb1b569706572702e7370696e2d66692e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01450b4cd2c1041e86dd7131ff0d0565112eb9a6eddf472ab0e40f117fae2e9e1b75736572732e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00a51296de1fa4bdb501f5e22e70bd7357c311eb96c480c7b5a83b0c73cac3a3a56f7261636c652d322e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c00ada0187c6e035b3726b80677a4dfe0b580ec9bf6fbea5ad9ddc5334377e4bd0f686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c006970f24b1c8d919325a5bf853410ed55ce3ebd1c7d209b7f44a4125ac9192b4a77616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c0051d453f91d122400d4ffea377689f251447437e4e870a159be8d3e9604b21e9c70726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c01b2bd890c05c3af200de1cd245cff4156daf7109813703e9642423b3e5c721967686f7477616c6c65742e6465762d6b61696368696e672e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c"
    // );

    //         if let ProofRequest::Bytes(full) =
    //             client.build_proof_request_bytes(&verify_release_id,
    // req.clone())         {
    //             assert_eq!(full.data.input, req.input);
    //             assert_eq!(full.parent_id, None);
    //             assert_eq!(full.files, None);
    //             assert_eq!(full.release_id, verify_release_id);
    //         } else {
    //             panic!("wrong request type");
    //         }

    //         let bytes = Circuit::Verify.with_selector(&req.input);
    //         pretty_assertions::assert_eq!(hex!(&bytes[4..]),
    // hex!(req.input));     }

    //     #[tokio::test]
    //     async fn test_verify() {
    //         let client = mocks().await;
    //         let txs =
    // fixture::<Vec<TransactionOrReceiptIdPrimitive>>("ids.json")
    //             .into_iter()
    //             .take(VERIFY_AMT)
    //             .collect_vec();

    //         let s = client.verify(txs, false).await.unwrap();
    //         println!("verify with {:?}", s);
    //     }

    //     #[tokio::test]
    //     async fn test_verify_relay() {
    //         let client = mocks().await;
    //         let txs =
    // fixture::<Vec<TransactionOrReceiptIdPrimitive>>("ids.json")
    //             .into_iter()
    //             .take(VERIFY_AMT)
    //             .collect_vec();

    //         let s = client.verify(txs, true).await.unwrap();
    //         println!("verify with {:?}", s);
    //     }

    //     #[tokio::test]
    //     async fn test_check_proof() {
    //         let client = mocks().await;
    //         let _proofs = client.fetch_proofs().await.unwrap();
    //     }
}

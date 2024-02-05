use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use futures::TryFutureExt;
use near_jsonrpc_client::{
    methods::{self, light_client_proof::RpcLightClientExecutionProofResponse},
    JsonRpcClient,
};
use near_primitives::views::{
    validator_stake_view::ValidatorStakeView, LightClientBlockView, ValidatorStakeViewV1,
};

use crate::prelude::*;

pub mod prelude;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum Network {
    Mainnet,
    #[default]
    Testnet,
    Localnet,
    Statelessnet,
}

impl Network {
    pub fn to_endpoint(&self) -> &str {
        const MAINNET_RPC_ENDPOINT: &str = "https://rpc.mainnet.near.org";
        const TESTNET_RPC_ENDPOINT: &str = "https://rpc.testnet.near.org";
        match self {
            Self::Mainnet => MAINNET_RPC_ENDPOINT,
            Self::Testnet => TESTNET_RPC_ENDPOINT,
            Self::Statelessnet => "https://rpc.statelessnet.near.org",
            _ => "http://`localhost:3030",
        }
    }
    pub fn archive_endpoint(&self) -> &str {
        const MAINNET_RPC_ARCHIVE_ENDPOINT: &str = "https://archival-rpc.mainnet.near.org";
        const TESTNET_RPC_ARCHIVE_ENDPOINT: &str = "https://archival-rpc.testnet.near.org";
        match self {
            Self::Mainnet => MAINNET_RPC_ARCHIVE_ENDPOINT,
            Self::Testnet => TESTNET_RPC_ARCHIVE_ENDPOINT,
            Self::Statelessnet => "https://archival-rpc.statelessnet.near.org",
            _ => "http://`localhost:3030",
        }
    }
}

impl From<usize> for Network {
    fn from(n: usize) -> Self {
        match n {
            0 => Self::Mainnet,
            1 => Self::Testnet,
            48 => Self::Statelessnet,
            _ => Self::Localnet,
        }
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Statelessnet => "statelessnet",
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
    pub async fn batch_fetch_proofs(
        &self,
        last_verified_hash: &CryptoHash,
        reqs: Vec<GetProof>,
        collect_errors: bool,
    ) -> Result<(Vec<BasicProof>, Vec<anyhow::Error>)> {
        let mut futs = vec![];
        for req in reqs {
            let proof = self.fetch_light_client_proof(req, *last_verified_hash);
            futs.push(proof);
        }
        let unpin_futs: Vec<_> = futs.into_iter().map(Box::pin).collect();

        let proofs: Vec<Result<BasicProof>> = futures::future::join_all(unpin_futs).await;
        let (proofs, errors): (Vec<_>, Vec<_>) = if collect_errors {
            proofs.into_iter().partition_result()
        } else {
            (proofs.into_iter().collect::<Result<Vec<_>>>()?, vec![])
        };
        Ok((proofs, errors))
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
                trace!("Error hitting main rpc, falling back to archive: {:?}", e);
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
                trace!("Error hitting main rpc, falling back to archive: {:?}", e);
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
        log::debug!("requesting validators: {:?}", req);
        self.client
            .call(&req)
            .or_else(|e| {
                trace!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .map(|x| x.current_validators)
            .map(|x| {
                x.into_iter()
                    .map(|x| {
                        ValidatorStakeView::V1(ValidatorStakeViewV1 {
                            account_id: x.account_id,
                            public_key: x.public_key,
                            stake: x.stake,
                        })
                    })
                    .collect()
            })
            .map_err(|e| anyhow::format_err!("{:?}:{}", epoch_id, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {}
}

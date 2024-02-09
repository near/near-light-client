use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
};

use async_trait::async_trait;
use futures::TryFutureExt;
use near_jsonrpc_client::{
    methods::{self, light_client_proof::RpcLightClientExecutionProofResponse},
    JsonRpcClient, MethodCallResult,
};
use near_primitives::{
    block_header::BlockHeader,
    views::{validator_stake_view::ValidatorStakeView, LightClientBlockView, ValidatorStakeViewV1},
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
    ) -> HashMap<CryptoHash, Result<BasicProof, anyhow::Error>> {
        let mut futs = vec![];
        for req in reqs {
            futs.push(Box::pin(async {
                (
                    match req {
                        near_primitives::types::TransactionOrReceiptId::Transaction {
                            transaction_hash,
                            ..
                        } => transaction_hash,
                        near_primitives::types::TransactionOrReceiptId::Receipt {
                            receipt_id,
                            ..
                        } => receipt_id,
                    },
                    self.fetch_light_client_proof(req, *last_verified_hash)
                        .await,
                )
            }));
        }

        let proofs: Vec<(CryptoHash, Result<BasicProof>)> = futures::future::join_all(futs).await;
        proofs.into_iter().fold(HashMap::new(), |mut acc, (r, p)| {
            acc.insert(r, p);
            acc
        })
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
    async fn fetch_header(&self, hash: &CryptoHash) -> Result<Header>;
}

#[async_trait]
impl LightClientRpc for NearRpcClient {
    async fn fetch_header(&self, hash: &CryptoHash) -> Result<Header> {
        let req = methods::block::RpcBlockRequest {
            block_reference: near_primitives::types::BlockReference::BlockId(
                near_primitives::types::BlockId::Hash(*hash),
            ),
        };
        self.client
            .call(&req)
            .or_else(|e| {
                trace!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .map_err(|e| anyhow!(e))
            .map(|x| x.header)
            .map(BlockHeader::from)
            .map(Into::into)
    }
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
        log::debug!("requesting proof: {:?}", req);
        self.client
            .call(&req)
            .or_else(|e| {
                trace!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .map_err(|e| anyhow::format_err!("{:?}:{}", req.id, e))
    }

    // It's cleaner to get epoch bps based on epoch id
    async fn fetch_epoch_bps(&self, epoch_id: &CryptoHash) -> Result<Vec<ValidatorStakeView>> {
        let req = methods::next_light_client_block::RpcLightClientNextBlockRequest {
            last_block_hash: *epoch_id,
        };
        log::debug!("requesting validators: {:?}", req);
        self.client
            .call(&req)
            .or_else(|e| {
                trace!("Error hitting main rpc, falling back to archive: {:?}", e);
                self.archive.call(&req)
            })
            .await
            .map_err(|e| anyhow::format_err!("{:?}", e))
            .and_then(|x| x.ok_or_else(|| anyhow::format_err!("no block found for {:?}", epoch_id)))
            .and_then(|x| {
                x.next_bps
                    .ok_or_else(|| anyhow::format_err!("no BPS found for {:?}", epoch_id))
            })
            .map_err(|e| anyhow::format_err!("{:?}:{}", epoch_id, e))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use near_primitives::{
        types::{BlockId, BlockReference, TransactionOrReceiptId},
        views::{BlockView, ChunkView},
    };

    use super::*;

    async fn fetch_chunk(c: &NearRpcClient, chunk_id: &CryptoHash) -> Result<ChunkView> {
        println!("fetching chunk: {:?}", chunk_id);
        let req = methods::chunk::RpcChunkRequest {
            chunk_reference: near_jsonrpc_primitives::types::chunks::ChunkReference::ChunkHash {
                chunk_id: *chunk_id,
            },
        };
        c.client
            .call(&req)
            .or_else(|e| {
                trace!("Error hitting main rpc, falling back to archive: {:?}", e);
                c.archive.call(&req)
            })
            .await
            .map_err(|e| anyhow::format_err!("{:?}", e))
    }

    async fn fetch_block(c: &NearRpcClient, block_reference: BlockReference) -> Result<BlockView> {
        println!("fetching block: {:?}", block_reference);
        let req = methods::block::RpcBlockRequest { block_reference };
        c.client
            .call(&req)
            .or_else(|e| {
                trace!("Error hitting main rpc, falling back to archive: {:?}", e);
                c.archive.call(&req)
            })
            .await
            .map_err(|e| anyhow::format_err!("{:?}", e))
    }

    async fn fetch_ids(client: &NearRpcClient, block: &BlockView) -> Vec<TransactionOrReceiptId> {
        let futs = block
            .chunks
            .iter()
            .map(|c| fetch_chunk(client, &c.chunk_hash).map(|x| x.unwrap()))
            .map(Box::pin)
            .collect_vec();
        let chunks = futures::future::join_all(futs).await;

        let receipts = chunks
            .iter()
            .map(|c| c.receipts.clone())
            .flatten()
            .map(|r| TransactionOrReceiptId::Receipt {
                receipt_id: r.receipt_id,
                receiver_id: r.receiver_id,
            })
            .collect_vec();
        let txs = chunks
            .iter()
            .map(|c| c.transactions.clone())
            .flatten()
            .map(|t| TransactionOrReceiptId::Transaction {
                transaction_hash: t.hash,
                sender_id: t.signer_id,
            })
            .collect_vec();

        vec![receipts, txs].concat()
    }

    #[tokio::test]
    async fn test_get_ids() {
        let client = NearRpcClient::new(Network::Testnet);

        let first_block = fetch_block(
            &client,
            BlockReference::BlockId(BlockId::Hash(
                CryptoHash::from_str("6taaeb6h2uJcuUvvmwXpYgagYvyHsFanWhm2ziGGHCff").unwrap(),
            )),
        )
        .await
        .unwrap()
        .header;

        let mut ids = vec![];

        let ids_to_fetch = 1024;

        let mut block = first_block.prev_hash;

        while ids.len() < ids_to_fetch {
            let next_block = fetch_block(&client, BlockReference::BlockId(BlockId::Hash(block)))
                .await
                .unwrap();
            ids.extend(fetch_ids(&client, &next_block).await);
            block = next_block.header.prev_hash;
        }

        std::fs::write("ids.json", serde_json::to_string(&ids).unwrap()).unwrap();

        // .and_then(|b| async {
        //     Ok(b.chunks
        //         .iter()
        //         .map(|c| fetch_chunk(&client, &c.chunk_hash))
        //         .map(Box::pin)
        //         .collect_vec())
        // })
        // .await;
        // For each in 0..10
        //
        // get parent block
        // get all chunks by chunk hash
        // get all receipts
        // get all txs
    }

    #[test]
    fn test_rpc() {
        todo!()
    }
}

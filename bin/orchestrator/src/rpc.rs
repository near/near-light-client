use std::net::SocketAddr;

use jsonrpsee::{
    proc_macros::rpc, server::Server, types::ErrorObjectOwned, PendingSubscriptionSink,
};
use jsonrpsee_core::{async_trait, SubscriptionResult};
use near_light_client_protocol::{
    config::ACCOUNT_DATA_SEPARATOR,
    prelude::{AccountId, BorshDeserialize, CryptoHash},
};
use near_light_client_rpc::{prelude::GetProof, TransactionOrReceiptId};
use tokio::task::JoinHandle;

use crate::{config::Config, succinct};

// TODO: share this with the circuit OR just make them dynamic with a max bound
const VERIFY_ID_AMT: usize = 128;

type Result<T> = core::result::Result<T, ErrorObjectOwned>;

pub struct RpcServerImpl {
    succinct_client: succinct::Client,
}

impl RpcServerImpl {
    pub fn new(succinct_client: succinct::Client) -> Self {
        Self { succinct_client }
    }
    pub async fn init(self, config: &Config) -> anyhow::Result<JoinHandle<()>> {
        let server = Server::builder()
            .build(config.host.parse::<SocketAddr>()?)
            .await?;
        let _addr = server.local_addr()?;
        let handle = server.start(self.into_rpc());
        Ok(tokio::spawn(handle.stopped()))
    }
}

#[rpc(server, namespace = "prove")]
pub trait ProveRpc {
    #[method(name = "sync")]
    async fn sync(
        &self,
        //body: plonky2x::backend::function::ProofRequestBase<BytesRequestData>,
    ) -> Result<CryptoHash>;

    #[method(name = "verify")]
    async fn verify(&self, ids: Vec<GetProof>) -> Result<CryptoHash>;

    #[subscription(name = "subscribe" => "override", item = Vec<ProofResultBase<BytesResultData>>)]
    async fn subscribe_proof(&self, keys: Option<Vec<String>>) -> SubscriptionResult;
}

#[async_trait]
impl ProveRpcServer for RpcServerImpl {
    async fn sync(
        &self,
        //body: plonky2x::backend::function::ProofRequestBase<BytesRequestData>,
    ) -> Result<CryptoHash> {
        // TODO: get trusted header hash from last_sync_proof or amortize
        let trusted_header_hash = CryptoHash::default();
        let req = self.succinct_client.build_sync_request(trusted_header_hash);
        let proof_id = self.succinct_client.send(req).await.unwrap();
        // TODO: Write hash(trusted_header_hash) => proof id to queue manager for
        // checking
        Ok(trusted_header_hash)
    }
    async fn verify(&self, mut ids: Vec<GetProof>) -> Result<CryptoHash> {
        // TODO: get trusted header hash from last_sync_proof or amortize
        let trusted_header_hash = CryptoHash::default();

        let id = CryptoHash::hash_bytes(
            &[
                trusted_header_hash.0.to_vec(),
                serde_json::to_vec(&ids).unwrap(),
            ]
            .concat(),
        );

        assert!(ids.len() <= VERIFY_ID_AMT);
        ids.resize(
            VERIFY_ID_AMT,
            GetProof::Transaction {
                transaction_hash: CryptoHash::default(),
                sender_id: AccountId::try_from_slice(&[ACCOUNT_DATA_SEPARATOR; AccountId::MAX_LEN])
                    .unwrap(),
            },
        );
        let req = self
            .succinct_client
            .build_verify_request(trusted_header_hash, ids);
        let proof_id = self.succinct_client.send(req).await.unwrap();
        // TODO:
        Ok(id)
    }
    async fn subscribe_proof(
        &self,
        pending: PendingSubscriptionSink,
        proofs: Option<Vec<String>>,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;
        // TODO: periodically query proofs and write them, write until timeout or
        // complete
        // TODO: spawn on a runner maybe
        Ok(())
    }
}

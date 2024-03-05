use std::{net::SocketAddr, sync::Arc, time::Duration};

use coerce::actor::LocalActorRef;
use flume::Sender;
use jsonrpsee::{
    proc_macros::rpc,
    server::Server,
    types::{ErrorCode, ErrorObjectOwned},
    PendingSubscriptionSink, SubscriptionMessage,
};
use jsonrpsee_core::{async_trait, SubscriptionResult};
use near_light_client_protocol::{
    config::ACCOUNT_DATA_SEPARATOR,
    prelude::{AccountId, BorshDeserialize, CryptoHash},
};
use near_light_client_rpc::{prelude::GetProof, TransactionOrReceiptId};
use plonky2x::backend::prover::ProofId;
use tokio::task::JoinHandle;

use crate::{
    config::Config,
    queue::{message::ProveTransaction, QueueManager},
    succinct,
};

// TODO: share this with the circuit OR just make them dynamic with a max bound
pub const VERIFY_ID_AMT: usize = 128;

type Result<T> = core::result::Result<T, ErrorObjectOwned>;

pub struct RpcServerImpl {
    succinct_client: Arc<succinct::Client>,
    queue: LocalActorRef<QueueManager>,
}

impl RpcServerImpl {
    pub fn new(succinct_client: Arc<succinct::Client>, queue: LocalActorRef<QueueManager>) -> Self {
        log::info!("starting rpc server");
        Self {
            succinct_client,
            queue,
        }
    }
    pub async fn run(self, config: &Config) -> anyhow::Result<JoinHandle<()>> {
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
    async fn sync(&self) -> Result<ProofId>;

    #[method(name = "verify")]
    async fn verify(&self, ids: Vec<GetProof>) -> Result<ProofId>;

    #[method(name = "push")]
    async fn push(&self, ids: Vec<GetProof>) -> Result<()>;

    #[subscription(name = "subscribe" => "override", item = Vec<ProofResponse>)]
    async fn subscribe_proof(&self, keys: Option<Vec<ProofId>>) -> SubscriptionResult;
}

#[async_trait]
impl ProveRpcServer for RpcServerImpl {
    async fn sync(&self) -> Result<ProofId> {
        let pid = self.succinct_client.sync().await.map_err(|e| {
            log::error!("{:?}", e);
            ErrorCode::ServerError(500)
        })?;
        Ok(pid)
    }
    async fn verify(&self, ids: Vec<GetProof>) -> Result<ProofId> {
        let pid = self.succinct_client.verify(ids).await.map_err(|e| {
            log::error!("{:?}", e);
            ErrorCode::ServerError(500)
        })?;
        Ok(pid)
    }
    async fn push(&self, ids: Vec<GetProof>) -> Result<()> {
        for tx in ids {
            self.queue
                .send(ProveTransaction { id: None, tx })
                .await
                .map_err(|e| {
                    log::error!("{:?}", e);
                    ErrorCode::ServerError(500)
                })?
                .unwrap();
        }
        Ok(())
    }
    async fn subscribe_proof(
        &self,
        pending: PendingSubscriptionSink,
        proofs: Option<Vec<ProofId>>,
    ) -> SubscriptionResult {
        // TODO: assert that these proofs arent in the queue already, or if they are,
        // help the queue manager out with the queries
        if let Some(mut proofs) = proofs {
            let sink = pending.accept().await?;

            let start_time = std::time::Instant::now();
            loop {
                let now = std::time::Instant::now();
                if now - start_time > Duration::from_secs(10) {
                    break;
                }
                let mut successful = vec![];
                for (i, id) in proofs.clone().iter().enumerate() {
                    let res = self.succinct_client.get(&id).await;
                    if let Ok(res) = res {
                        let msg = SubscriptionMessage::from_json(&res).unwrap();
                        sink.send(msg).await.unwrap();
                        successful.push(i);
                    }
                }
                successful.sort();
                successful.reverse();
                for i in successful {
                    proofs.remove(i);
                }
            }
        }
        Ok(())
    }
}

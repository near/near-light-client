use coerce::actor::{
    context::ActorContext,
    message::{Handler, Message},
    Actor,
};
use near_primitives::types::TransactionOrReceiptId;
use protocol::{experimental::Proof as ExperimentalProof, Proof};

use super::LightClient;
// TODO: convert to actix
use crate::prelude::*;

pub struct Shutdown;

impl Message for Shutdown {
    type Result = Result<()>;
}

pub struct Head;

impl Message for Head {
    type Result = Option<Header>;
}

pub struct Archive {
    pub epoch: CryptoHash,
}

impl Message for Archive {
    type Result = Option<Header>;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetProof(pub TransactionOrReceiptId);

impl Message for GetProof {
    type Result = Option<super::Proof>;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BatchGetProof(pub Vec<GetProof>);

impl Message for BatchGetProof {
    type Result = Option<ExperimentalProof>;
}

pub struct VerifyProof {
    pub proof: Proof,
}

impl Message for VerifyProof {
    type Result = Result<bool>;
}
#[async_trait]
impl Actor for LightClient {
    async fn started(&mut self, _ctx: &mut ActorContext) {
        self.bootstrap_store()
            .await
            .expect("Failed to bootstrap store");
        // TODO: anonymous ctx.spawn(id, actor)
        let catchup = self.config.catchup;
        let store = self.store.clone();
        let client = self.client.clone();
        tokio::task::spawn(async move { Self::start_syncing(catchup, store, client).await });
    }
}

#[async_trait]
impl Handler<Head> for LightClient {
    async fn handle(
        &mut self,
        _message: Head,
        _ctx: &mut ActorContext,
    ) -> <Head as coerce::actor::message::Message>::Result {
        self.store.head().await.ok()
    }
}

#[async_trait]
impl Handler<Archive> for LightClient {
    async fn handle(
        &mut self,
        message: Archive,
        _ctx: &mut ActorContext,
    ) -> <Archive as coerce::actor::message::Message>::Result {
        self.header(message.epoch).await
    }
}

#[async_trait]
impl Handler<Shutdown> for LightClient {
    async fn handle(
        &mut self,
        _message: Shutdown,
        ctx: &mut ActorContext,
    ) -> <Shutdown as coerce::actor::message::Message>::Result {
        self.store.shutdown().await;
        ctx.stop(None);
        Ok(())
    }
}

#[async_trait]
impl Handler<GetProof> for LightClient {
    async fn handle(
        &mut self,
        message: GetProof,
        _ctx: &mut ActorContext,
    ) -> <GetProof as coerce::actor::message::Message>::Result {
        self.get_proofs(BatchGetProof(vec![message]))
            .await
            .ok()
            .and_then(|proofs| proofs.into_iter().next())
    }
}

#[async_trait]
impl Handler<VerifyProof> for LightClient {
    async fn handle(
        &mut self,
        message: VerifyProof,
        _ctx: &mut ActorContext,
    ) -> <VerifyProof as coerce::actor::message::Message>::Result {
        self.verify_proof(message.proof).await.map_err(|e| {
            log::error!("{:?}", e);
            e
        })
    }
}

#[async_trait]
impl Handler<BatchGetProof> for LightClient {
    async fn handle(
        &mut self,
        message: BatchGetProof,
        _ctx: &mut ActorContext,
    ) -> <BatchGetProof as coerce::actor::message::Message>::Result {
        self.experimental_get_proofs(message).await.ok()
    }
}

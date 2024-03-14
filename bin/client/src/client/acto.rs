use actix::prelude::*;
use near_primitives::types::TransactionOrReceiptId;
use protocol::{experimental::Proof as ExperimentalProof, Proof};

use super::LightClient;
use crate::prelude::*;

impl Actor for LightClient {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        self.bootstrap_store().expect("Failed to bootstrap store");

        let catchup = self.config.catchup;
        let store = self.store.clone();
        let client = self.client.clone();
        actix::spawn(async move {
            LightClient::start_syncing(catchup, store, client).await;
        });
    }
}

#[derive(Message)]
#[rtype(result = "Option<Header>")]
pub struct Head;

impl Handler<Head> for LightClient {
    type Result = Option<Header>;

    fn handle(&mut self, _message: Head, _ctx: &mut Self::Context) -> Self::Result {
        actix::spawn(async move { self.store.head().await.ok() })
            .into_actor(self)
            .wait()
    }
}

#[derive(Message)]
#[rtype(result = "Option<Header>")]
pub struct Archive {
    pub epoch: CryptoHash,
}

impl Handler<Archive> for LightClient {
    type Result = Option<Header>;

    fn handle(&mut self, message: Archive, _ctx: &mut Self::Context) -> Self::Result {
        actix::spawn(async move { self.header(message.epoch).await })
            .into_actor(self)
            .wait()
    }
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct Shutdown;

impl Handler<Shutdown> for LightClient {
    type Result = Result<(), ()>;

    fn handle(&mut self, _message: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        actix::spawn(async move {
            self.store.shutdown().await;
        })
        .into_actor(self)
        .map(|_result, _actor, ctx| {
            ctx.stop();
            Ok(())
        })
        .wait()
    }
}

#[derive(Debug, Deserialize, Serialize, Message)]
#[rtype(result = "Option<super::Proof>")]
pub struct GetProof(pub TransactionOrReceiptId);

impl Handler<GetProof> for LightClient {
    type Result = Option<super::Proof>;

    fn handle(&mut self, message: GetProof, _ctx: &mut Self::Context) -> Self::Result {
        actix::spawn(async move {
            self.get_proofs(BatchGetProof(vec![message]))
                .await
                .ok()
                .and_then(|proofs| proofs.into_iter().next())
        })
        .into_actor(self)
        .wait()
    }
}

#[derive(Message)]
#[rtype(result = "Result<bool>")]
pub struct VerifyProof {
    pub proof: Proof,
}

impl Handler<VerifyProof> for LightClient {
    type Result = Result<bool, ()>;

    fn handle(&mut self, message: VerifyProof, _ctx: &mut Self::Context) -> Self::Result {
        actix::spawn(async move {
            self.verify_proof(message.proof).await.map_err(|e| {
                log::error!("{:?}", e);
                ()
            })
        })
        .into_actor(self)
        .wait()
    }
}

#[derive(Debug, Deserialize, Serialize, Message)]
#[rtype(result = "Option<ExperimentalProof>")]
pub struct BatchGetProof(pub Vec<GetProof>);

impl Handler<BatchGetProof> for LightClient {
    type Result = Option<ExperimentalProof>;

    fn handle(&mut self, message: BatchGetProof, _ctx: &mut Self::Context) -> Self::Result {
        actix::spawn(async move { self.experimental_get_proofs(message).await.ok() })
            .into_actor(self)
            .wait()
    }
}

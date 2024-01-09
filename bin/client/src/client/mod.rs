use self::{message::BatchGetProof, store::Store};
use crate::prelude::*;
use crate::{
    client::{
        protocol::Proof,
        protocol::Protocol,
        store::{head_key, Collection, Entity},
    },
    config::Config,
};
use coerce::actor::{context::ActorContext, message::Handler, Actor};
use message::{Archive, GetProof, Head, Shutdown, VerifyProof};
use near_primitives::views::validator_stake_view::ValidatorStakeView;
use std::{str::FromStr, sync::Arc};
use tokio::time;

pub mod error;
pub mod message;
pub mod protocol;
pub mod rpc;
mod store;

pub struct LightClient {
    config: Config,
    client: rpc::NearRpcClient,
    store: Arc<Store<store::sled::Store>>,
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

impl LightClient {
    pub fn new(config: &Config) -> Result<Self> {
        let client = rpc::NearRpcClient::new(config.network.clone());

        // TODO: store selector in config
        let store = store::sled::init(config)?;

        Ok(Self {
            client,
            config: config.clone(),
            store: Store(store.into()).into(),
        })
    }

    async fn bootstrap_store(&mut self) -> Result<()> {
        let head = self.store.head().await;
        if head.is_err() {
            let sync_from =
                CryptoHash::from_str(&self.config.starting_head).map_err(anyhow::Error::msg)?;

            let starting_head = self
                .client
                .fetch_latest_header(&sync_from)
                .await
                .ok_or_else(|| anyhow::anyhow!("We need a starting header"))?;

            log::info!("starting head: {:?}", starting_head.inner_lite.height);

            let mut inserts: Vec<(CryptoHash, Entity)> = vec![];

            inserts.push((
                starting_head.inner_lite.epoch_id,
                starting_head
                    .next_bps
                    .ok_or_else(|| anyhow::anyhow!("next_bps should be Some for boostrapped head"))?
                    .into_iter()
                    .map(ValidatorStakeView::into_validator_stake)
                    .collect_vec()
                    .into(),
            ));

            let boostrapped_head = Header {
                prev_block_hash: starting_head.prev_block_hash,
                inner_rest_hash: starting_head.inner_rest_hash,
                inner_lite: starting_head.inner_lite,
            };

            inserts.push((head_key(), boostrapped_head.into()));

            self.store.insert(&inserts).await?;
        }

        Ok(())
    }

    // TODO: dynamically determine if should catchup
    pub async fn start_syncing(
        mut catching_up: bool,
        store: Arc<Store<store::sled::Store>>,
        client: rpc::NearRpcClient,
    ) {
        // TODO: make configurable, currently set to ~block time
        let default_duration = time::Duration::from_secs(2);

        loop {
            let duration = if catching_up {
                time::Duration::from_millis(100)
            } else {
                default_duration
            };
            tokio::select! {
                r = Self::sync(store.clone(), client.clone()) => {
                    tokio::time::sleep(duration).await;
                    match r {
                        Err(e) => {
                            log::error!("Error syncing: {:?}", e);
                            catching_up = false;
                        },
                        Ok(false) if catching_up => {
                            log::debug!("Slowing down sync interval to {:?}", default_duration);
                            catching_up = false;
                        }
                        _ => (),
                    }
                }
            }
        }
    }
    pub async fn sync(
        store: Arc<Store<store::sled::Store>>,
        client: rpc::NearRpcClient,
    ) -> Result<bool> {
        let head = store.head().await?;
        log::debug!("Current head: {:#?}", head.inner_lite);

        let next_header = client
            .fetch_latest_header(
                &CryptoHash::from_str(&format!("{}", head.hash()))
                    .map_err(|e| anyhow!("Failed to parse hash: {:?}", e))?,
            )
            .await
            .ok_or_else(|| anyhow!("Failed to fetch latest header"))?;
        log::trace!("Got new header: {:#?}", next_header.inner_lite);

        let bps = store
            .get(&Collection::BlockProducers, &head.inner_lite.epoch_id)
            .await
            .and_then(|x| x.bps())?;

        let synced = Protocol::sync(&head, &bps, next_header)?;

        let mut inserts: Vec<(CryptoHash, Entity)> = vec![];

        if let Some((epoch, next_bps)) = synced.next_bps {
            log::debug!("storing next bps[{:?}]", epoch);
            inserts.push((epoch.0, next_bps.into()));
        }

        inserts.push((head.inner_lite.epoch_id, synced.new_head.clone().into()));
        inserts.push((head_key(), synced.new_head.into()));

        store.insert(&inserts).await?;
        Ok(true)
    }

    async fn header(&self, epoch: CryptoHash) -> Option<Header> {
        self.store
            .get(&Collection::Headers, &epoch)
            .await
            .and_then(|e| e.header())
            .ok()
    }

    pub async fn batch_fetch_proofs(
        &self,
        last_verified_hash: &CryptoHash,
        p: BatchGetProof,
        collect_errors: bool,
    ) -> Result<(Vec<BasicProof>, Vec<anyhow::Error>)> {
        let mut futs = vec![];
        for req in p.0 {
            let proof = self
                .client
                .fetch_light_client_proof(req, *last_verified_hash);
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

    pub async fn verify_proof(&self, p: Proof) -> Result<bool> {
        anyhow::ensure!(
            self.store
                .contains(&Collection::UsedRoots, p.block_merkle_root())
                .await?,
            "Root {:?} is not known",
            p.block_merkle_root()
        );
        Protocol::inclusion_proof_verify(p)
    }

    // TODO: this and below are the same except from two lines
    pub async fn get_proofs(&self, p: BatchGetProof) -> Result<Vec<Proof>> {
        let head = self.store.head().await?;
        let proofs = self.batch_fetch_proofs(&head.hash(), p, false).await?.0;

        self.store
            .insert(&[(head.inner_lite.block_merkle_root, Entity::UsedRoot)])
            .await?;
        Ok(proofs
            .into_iter()
            .map(|x| (head.inner_lite.block_merkle_root, x))
            .map(Into::into)
            .collect())
    }

    pub async fn experimental_get_proofs(
        &self,
        p: BatchGetProof,
    ) -> Result<(ExperimentalProof, Vec<anyhow::Error>)> {
        let head = self.store.head().await?;
        let (proofs, errors) = self.batch_fetch_proofs(&head.hash(), p, true).await?;
        let p = protocol::experimental::Proof::new(head.inner_lite.block_merkle_root, proofs);
        self.store
            .insert(&[(head.inner_lite.block_merkle_root, Entity::UsedRoot)])
            .await?;

        Ok((p, errors))
    }
}

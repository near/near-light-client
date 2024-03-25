use std::{sync::Arc, time::Duration};

use actix::prelude::*;
use anyhow::{anyhow, Result};
use futures::FutureExt;
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use near_light_client_rpc::{prelude::Itertools, TransactionOrReceiptId};
use near_light_clientx::config::bps_from_network;
use priority_queue::PriorityQueue;
use serde::{Deserialize, Serialize};
pub use types::RegistryInfo;

use self::types::{PriorityWeight, TransactionOrReceiptIdNewtype};
use crate::succinct::{
    self,
    types::{ProofResponse, ProofStatus},
    ProofId,
};

mod types;

// TODO[Optimisation]: decide if we can try to identity hash based on ids,
// they're already hashed, perhaps a collision would be if receipt_id ++ tx_id
// are the same, unlikely
type Queue = PriorityQueue<TransactionOrReceiptIdNewtype, PriorityWeight, DefaultHashBuilder>;

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    drain_interval: u64,
    sync_interval: u64,
    cleanup_interval: u64,
    persist_interval: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            drain_interval: 1,
            sync_interval: 60 * 30,
            cleanup_interval: 60,
            persist_interval: 30,
        }
    }
}

pub struct Engine {
    registry: HashMap<usize, RegistryInfo>,
    succinct_client: Arc<succinct::Client>,
    proving_queue: Queue,
    batches: HashMap<u32, Option<ProofId>>,
    request_info: HashMap<ProofId, Option<ProofStatus>>,
    config: Config,
    verify_amt: usize,
}

impl Engine {
    pub fn new(config: &super::Config, succinct_client: Arc<succinct::Client>) -> Self {
        log::info!("starting queue manager");

        let state = PersistedState::try_from("state.json");

        Self {
            registry: state
                .as_ref()
                .map(|s| s.registry.clone())
                .unwrap_or_default(),
            succinct_client,
            proving_queue: state
                .as_ref()
                .map(|s| Queue::from_iter(s.queue.clone().into_iter()))
                .unwrap_or(Queue::with_default_hasher()),
            batches: state
                .as_ref()
                .map(|s| s.batches.clone())
                .unwrap_or_default(),
            request_info: state.map(|s| s.request_info).unwrap_or_default(),
            config: config.engine.clone(),
            verify_amt: bps_from_network(&config.rpc.network),
        }
    }

    fn prove(
        &mut self,
        id: Option<usize>,
        tx: TransactionOrReceiptId,
    ) -> <ProveTransaction as Message>::Result {
        let weight = if let Some(id) = id {
            self.registry
                .get(&id)
                .ok_or_else(|| anyhow!("id not found"))?
                .weight
        } else {
            1
        };
        log::debug!("enqueuing {:?} with weight: {weight}", tx);
        self.proving_queue.push(tx.into(), weight);
        Ok(())
    }

    fn make_batch(&mut self) -> Option<(u32, Vec<TransactionOrReceiptId>)> {
        if self.proving_queue.len() < self.verify_amt {
            return None;
        }
        let id = self.batches.len() as u32;
        let mut txs = vec![];
        for _ in 0..self.verify_amt {
            let (req, _) = self.proving_queue.pop()?;
            txs.push(req.0);
        }
        self.batches.insert(id, None);
        Some((id, txs))
    }
}

impl Actor for Engine {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.run_interval(Duration::from_secs(self.config.drain_interval), |_, ctx| {
            ctx.address().do_send(Drain)
        });
        ctx.run_interval(Duration::from_secs(self.config.sync_interval), |_, ctx| {
            ctx.address().do_send(Sync)
        });
        ctx.run_interval(
            Duration::from_secs(self.config.cleanup_interval),
            |_, ctx| ctx.address().do_send(Cleanup),
        );
        ctx.run_interval(
            Duration::from_secs(self.config.persist_interval),
            |_, ctx| ctx.address().do_send(Persist),
        );
    }
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct ProveTransaction {
    pub id: Option<usize>,
    pub tx: TransactionOrReceiptId,
}

impl Handler<ProveTransaction> for Engine {
    type Result = Result<()>;

    fn handle(&mut self, msg: ProveTransaction, _ctx: &mut Self::Context) -> Self::Result {
        self.prove(msg.id, msg.tx)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Message)]
#[rtype(result = "Result<ProofResponse>")]
pub struct CheckProof(pub ProofId);

impl From<ProofId> for CheckProof {
    fn from(id: ProofId) -> Self {
        Self(id)
    }
}

// TODO: change to periodic job to check proofs for all batches and clean up
impl Handler<CheckProof> for Engine {
    type Result = ResponseFuture<Result<ProofResponse>>;

    fn handle(&mut self, _msg: CheckProof, _ctx: &mut Self::Context) -> Self::Result {
        // // This feels like a succinct client job, keep checking queues
        // let fut = self.check_proof(msg.0);
        // Box::pin(fut)
        todo!()
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Register(pub RegistryInfo);

impl Handler<Register> for Engine {
    type Result = ();

    fn handle(&mut self, msg: Register, _ctx: &mut Self::Context) -> Self::Result {
        self.registry.insert(msg.0.id, msg.0);
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Sync;

impl Handler<Sync> for Engine {
    type Result = AtomicResponse<Self, ()>;

    fn handle(&mut self, _msg: Sync, _ctx: &mut Self::Context) -> Self::Result {
        let client = self.succinct_client.clone();
        // Not ssure this needs atomic
        AtomicResponse::new(Box::pin(
            async move { client.sync(true).await.unwrap() }
                .into_actor(self)
                .map(move |r, this, _| {
                    log::debug!("sync requested {:?}", r);
                    this.request_info.insert(r, None);
                }),
        ))
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Drain;

impl Handler<Drain> for Engine {
    type Result = AtomicResponse<Self, ()>;

    fn handle(&mut self, _msg: Drain, _ctx: &mut Self::Context) -> Self::Result {
        AtomicResponse::new(if let Some((id, batch)) = self.make_batch() {
            let client = self.succinct_client.clone();
            let fut = async move { client.verify(batch, true).await.unwrap() }
                // Then ask succinct to verify
                .into_actor(self)
                // Once verify proof id is returned, write the result to ourselves
                .map(move |r, this, _| {
                    this.batches.get_mut(&id).unwrap().replace(r);
                    log::debug!("batch {id} done, batches: {:?}", this.batches);
                });
            Box::pin(fut)
        } else {
            Box::pin(async {}.into_actor(self))
        })
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Cleanup;

impl Handler<Cleanup> for Engine {
    type Result = AtomicResponse<Self, ()>;

    fn handle(&mut self, _msg: Cleanup, _ctx: &mut Self::Context) -> Self::Result {
        log::trace!("cleaning up");

        let to_check = self
            .batches
            .clone()
            .into_iter()
            .filter_map(|(_, pid)| pid)
            .filter(|pid| self.request_info.get(pid).is_none())
            .take(30) // TODO: configure
            .collect_vec();

        if to_check.is_empty() {
            return AtomicResponse::new(Box::pin(async {}.into_actor(self)));
        }

        let client = self.succinct_client.clone();
        // Not ssure this needs atomic
        AtomicResponse::new(Box::pin(
            async move {
                let mut futs = vec![];
                log::debug!("checking on {} proofs", to_check.len());
                for pid in to_check {
                    futs.push(client.get_proof(pid).map(move |p| (pid, p)));
                }
                futures::future::join_all(futs).await
            }
            .into_actor(self)
            .map(move |r, this, _| {
                r.into_iter().for_each(|(pid, p)| match p {
                    Ok(p) => {
                        log::debug!("proof: {:?} status: {:?}", pid, p.status);
                        this.request_info.insert(pid, Some(p.status));
                    }
                    Err(e) => {
                        log::error!("{:?}", e);
                    }
                });
            }),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    registry: HashMap<usize, RegistryInfo>,
    batches: HashMap<u32, Option<ProofId>>,
    request_info: HashMap<ProofId, Option<ProofStatus>>,
    queue: HashMap<TransactionOrReceiptIdNewtype, u32>,
}

impl TryFrom<&str> for PersistedState {
    type Error = anyhow::Error;
    fn try_from(s: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(s);
        if let Ok(contents) = contents {
            let s = serde_json::from_str(&contents)?;
            Ok(s)
        } else {
            anyhow::bail!("Failed to read state file")
        }
    }
}

#[derive(Message)]
#[rtype(result = "anyhow::Result<()>")]
pub struct Persist;

impl Handler<Persist> for Engine {
    type Result = anyhow::Result<()>;

    fn handle(&mut self, _msg: Persist, _ctx: &mut Self::Context) -> Self::Result {
        log::trace!("persisting state");
        let state = PersistedState {
            registry: self.registry.clone(),
            batches: self.batches.clone(),
            request_info: self.request_info.clone(),
            queue: self
                .proving_queue
                .clone()
                .into_sorted_iter()
                .map(|(i, w)| (i, w))
                .collect(),
        };
        std::fs::write("state.json", serde_json::to_string(&state)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use near_light_client_rpc::TransactionOrReceiptId;
    use test_utils::fixture;

    use super::*;
    use crate::succinct::tests::mocks;

    const VERIFY_AMT: usize = 64;

    async fn manager() -> Engine {
        let client = mocks().await;
        Engine::new(Arc::new(client))
    }

    // TODO: move to integration tests
    // #[ignore = "test is a live e2e test"]
    // #[tokio::test]
    // async fn e2e_test_verify() {
    //     let mut m = manager().await;
    //
    //     let fixture = fixture::<Vec<TransactionOrReceiptId>>("ids.json");
    //     let fixtures = fixture.iter().take(VERIFY_AMT);
    //     for r in fixtures {
    //         m.prove(message::ProveTransaction {
    //             tx: r.clone(),
    //             id: None,
    //         })
    //         .await
    //         .unwrap();
    //     }
    //     QueueManager::try_drain(m.succinct_client, m.proving_queue).await;
    // }

    // #[tokio::test]
    // async fn test_check_proof() {
    //     let m = manager().await;
    //
    //     let _r = m
    //         .check_proof(ProofId(Stubs::verify_pid()).into())
    //         .await
    //         .unwrap();
    // }

    #[tokio::test]
    async fn test_weights() {
        let mut m = manager().await;

        let fixture = fixture::<Vec<TransactionOrReceiptId>>("ids.json");
        let to_take = VERIFY_AMT - 1;
        let fixtures = fixture.clone().into_iter().take(to_take);
        let priority_from = VERIFY_AMT - 7;

        let mut priority: Vec<TransactionOrReceiptIdNewtype> = vec![];

        for (i, r) in fixtures.enumerate() {
            let id = if i >= priority_from {
                m.registry.insert(
                    i,
                    RegistryInfo {
                        id: i,
                        weight: i as u32,
                    },
                );
                // Store the prioritsed entries
                priority.push(r.clone().into());
                Some(i)
            } else {
                None
            };
            m.prove(id, r).unwrap();
        }

        let mut check_queue = m.proving_queue.clone();

        let mut i = to_take - 1;
        while let Some((tx, w)) = check_queue.pop() {
            if i >= priority_from {
                assert_eq!(i as u32, w);
                assert!(priority.contains(&tx));
                i -= 1;
            } else {
                assert_eq!(w, 1)
            }
        }

        let (tx, w) = m.proving_queue.pop().unwrap();
        // Make empty batch, since theres not enough to fill
        let batch = m.make_batch();
        assert!(batch.is_none());

        // Put the tx we took back
        m.prove(Some(w as usize), tx.0).unwrap();
        m.prove(None, fixture.last().unwrap().clone()).unwrap();
        println!("{}", m.proving_queue.len());

        let (id, batch) = m.make_batch().unwrap();
        assert_eq!(id, 0);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_persist() {}
}

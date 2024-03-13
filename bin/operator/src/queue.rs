use std::{sync::Arc, time::Duration};

use actix::{prelude::*, Addr};
use anyhow::{anyhow, ensure, Result};
use futures::{FutureExt, TryFutureExt};
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use near_light_client_rpc::{prelude::Itertools, TransactionOrReceiptId};
use plonky2x::backend::prover::ProofId;
use priority_queue::PriorityQueue;
pub use types::RegistryInfo;

use self::types::{PriorityWeight, TransactionOrReceiptIdNewtype};
use crate::{
    rpc::VERIFY_ID_AMT,
    succinct::{
        self,
        types::{ProofResponse, ProofStatus},
    },
};

mod types;

// TODO: decide if we can try to identity hash based on ids, they're already
// hashed
// Collision <> receipt & tx?
type Queue = PriorityQueue<TransactionOrReceiptIdNewtype, PriorityWeight, DefaultHashBuilder>;

/// An in memory queue as a placeholder until we decide on the flow
pub struct QueueManager {
    registry: HashMap<usize, RegistryInfo>,
    succinct_client: Arc<succinct::Client>,
    // TODO: persist me
    proving_queue: Queue,
    batches: HashMap<u32, Option<ProofId>>,
    request_info: HashMap<ProofId, Option<ProofStatus>>,
}

impl QueueManager {
    pub fn new(
        registry: HashMap<usize, RegistryInfo>,
        succinct_client: Arc<succinct::Client>,
    ) -> Self {
        log::info!("starting queue manager");
        let proving_queue = Queue::with_default_hasher();

        Self {
            registry,
            succinct_client,
            proving_queue,
            batches: Default::default(),
            request_info: Default::default(),
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
        log::debug!("adding to {:?} with weight: {weight}", tx);
        self.proving_queue.push(tx.into(), weight);
        Ok(())
    }

    async fn check_proof(&self, msg: ProofId) -> <CheckProof as Message>::Result {
        let mut poll_count = 0;
        // TODO: configure
        let sleep = tokio::time::sleep(Duration::from_secs(60));
        tokio::pin!(sleep);

        loop {
            if let Ok(proof) = self.succinct_client.get_proof(msg.clone()).await {
                match proof.status {
                    ProofStatus::Success => {
                        break Ok(proof);
                    }
                    ProofStatus::Failure => break Ok(proof),
                    _ => {}
                }
            }
            poll_count += 1;
            ensure!(poll_count < 10, "failed to get proof");
            sleep.as_mut().await;
        }
    }

    fn make_batch(&mut self) -> (u32, Vec<TransactionOrReceiptId>) {
        let mut id = 0;
        let mut txs = vec![];
        if self.proving_queue.len() >= VERIFY_ID_AMT {
            for _ in 0..VERIFY_ID_AMT {
                let (req, _) = self.proving_queue.pop().unwrap();
                txs.push(req.0);
            }
        }
        if !txs.is_empty() {
            let new_id = self.batches.len() as u32;
            self.batches.insert(new_id, None);
            id = new_id;
        }
        (id, txs)
    }
}

impl Actor for QueueManager {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.run_interval(Duration::from_secs(1), |_, ctx| {
            ctx.address().do_send(Drain)
        });
        ctx.run_interval(Duration::from_secs(60 * 60), |_, ctx| {
            ctx.address().do_send(Sync)
        });
        ctx.run_interval(Duration::from_secs(60), |_, ctx| {
            ctx.address().do_send(Cleanup)
        });
    }
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct ProveTransaction {
    pub id: Option<usize>,
    pub tx: TransactionOrReceiptId,
}

impl Handler<ProveTransaction> for QueueManager {
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
impl Handler<CheckProof> for QueueManager {
    type Result = ResponseFuture<Result<ProofResponse>>;

    fn handle(&mut self, msg: CheckProof, _ctx: &mut Self::Context) -> Self::Result {
        // // This feels like a succinct client job, keep checking queues
        // let fut = self.check_proof(msg.0);
        // Box::pin(fut)
        todo!()
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Register(pub RegistryInfo);

impl Handler<Register> for QueueManager {
    type Result = ();

    fn handle(&mut self, msg: Register, _ctx: &mut Self::Context) -> Self::Result {
        self.registry.insert(msg.0.id, msg.0);
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Sync;

impl Handler<Sync> for QueueManager {
    type Result = AtomicResponse<Self, ()>;

    fn handle(&mut self, _msg: Sync, _ctx: &mut Self::Context) -> Self::Result {
        let client = self.succinct_client.clone();
        // Not ssure this needs atomic
        AtomicResponse::new(Box::pin(
            async move { client.sync(true).await.unwrap() }
                .into_actor(self)
                .map(move |r, this, _| {
                    log::debug!("syncing {:?}", r);
                    this.request_info.insert(r, None);
                }),
        ))
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Drain;

impl Handler<Drain> for QueueManager {
    type Result = AtomicResponse<Self, ()>;

    fn handle(&mut self, _msg: Drain, _ctx: &mut Self::Context) -> Self::Result {
        // First pull the correct transactions
        // Create batch and write it
        let (id, batch) = self.make_batch();
        // TODO: cleanup/retry procedures
        //
        if batch.is_empty() {
            return AtomicResponse::new(Box::pin(async {}.into_actor(self)));
        }

        let client = self.succinct_client.clone();
        // Not ssure this needs atomic
        AtomicResponse::new(Box::pin(
            async move { client.verify(batch, true).await.unwrap() }
                // Then ask succinct to verify
                .into_actor(self)
                // Once verify proof id is returned, write the result to ourselves
                .map(move |r, this, _| {
                    this.batches.get_mut(&id).unwrap().replace(r);
                    log::debug!("batch {id} done, batches: {:?}", this.batches);
                }),
        ))
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Cleanup;

impl Handler<Cleanup> for QueueManager {
    type Result = AtomicResponse<Self, ()>;

    fn handle(&mut self, _msg: Cleanup, _ctx: &mut Self::Context) -> Self::Result {
        log::debug!("cleaning up");
        // Need to check the proofs, update their state here if they
        // are broken OR if they need to be relayed to the gateway manually
        //
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
                        log::debug!("proof {:?} done: {:?}", pid, p);
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

#[cfg(test)]
mod tests {

    use near_light_client_rpc::TransactionOrReceiptId;
    use plonky2x::backend::prover::ProofId;
    use test_utils::fixture;

    use super::*;
    use crate::{succinct::tests::mocks, tests::Stubs};

    async fn manager() -> QueueManager {
        let client = mocks().await;
        QueueManager::new(Default::default(), Arc::new(client))
    }

    // TODO: move to integration tests
    // #[ignore = "test is a live e2e test"]
    // #[tokio::test]
    // async fn e2e_test_verify() {
    //     let mut m = manager().await;
    //
    //     let fixture = fixture::<Vec<TransactionOrReceiptId>>("ids.json");
    //     let fixtures = fixture.iter().take(VERIFY_ID_AMT);
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

    #[tokio::test]
    async fn test_check_proof() {
        let m = manager().await;

        let r = m
            .check_proof(ProofId(Stubs::verify_pid()).into())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_weights() {
        let mut m = manager().await;

        let fixture = fixture::<Vec<TransactionOrReceiptId>>("ids.json");
        let to_take = VERIFY_ID_AMT - 1;
        let fixtures = fixture.clone().into_iter().take(to_take);
        let priority_from = VERIFY_ID_AMT - 7;

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
        let (id, batch) = m.make_batch();
        assert_eq!(id, 0);
        assert!(batch.is_empty());

        // Put the tx we took back
        m.prove(Some(w as usize), tx.0).unwrap();
        m.prove(None, fixture.last().unwrap().clone()).unwrap();
        println!("{}", m.proving_queue.len());

        let (id, batch) = m.make_batch();
        assert_eq!(id, 0);
        assert!(!batch.is_empty());
    }
}

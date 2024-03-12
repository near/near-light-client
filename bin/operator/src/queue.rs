use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, ensure};
use coerce::actor::{
    context::ActorContext,
    message::{Handler, Message},
    Actor,
};
use hashbrown::{hash_map::DefaultHashBuilder, HashMap};
use jsonrpsee_core::async_trait;
use near_light_client_rpc::{prelude::GetProof, TransactionOrReceiptId};
use priority_queue::PriorityQueue;
use tokio::sync::RwLock;

use crate::{
    rpc::VERIFY_ID_AMT,
    succinct::{
        self,
        types::{ProofResponse, ProofStatus},
    },
};

// TODO: weights management
type PriorityWeight = u32;

#[derive(Debug, Clone)]
pub struct TransactionOrReceiptIdNewtype(pub TransactionOrReceiptId);

impl From<TransactionOrReceiptId> for TransactionOrReceiptIdNewtype {
    fn from(id: TransactionOrReceiptId) -> Self {
        Self(id)
    }
}

impl std::hash::Hash for TransactionOrReceiptIdNewtype {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let (is_transaction, id, account) = match &self.0 {
            GetProof::Transaction {
                transaction_hash,
                sender_id,
            } => (true, transaction_hash, sender_id),
            GetProof::Receipt {
                receipt_id,
                receiver_id,
            } => (false, receipt_id, receiver_id),
        };
        is_transaction.hash(state);
        id.hash(state);
        account.hash(state);
    }
}

impl PartialEq for TransactionOrReceiptIdNewtype {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (
                TransactionOrReceiptId::Transaction {
                    transaction_hash: l1,
                    sender_id: l2,
                },
                TransactionOrReceiptId::Transaction {
                    transaction_hash: r1,
                    sender_id: r2,
                },
            ) => l1 == r1 && l2 == r2,
            (
                TransactionOrReceiptId::Receipt {
                    receipt_id: l1,
                    receiver_id: l2,
                },
                TransactionOrReceiptId::Receipt {
                    receipt_id: r1,
                    receiver_id: r2,
                },
            ) => l1 == r1 && l2 == r2,
            _ => false,
        }
    }
}

impl Eq for TransactionOrReceiptIdNewtype {}

#[derive(Debug)]
pub struct RegistryInfo {
    pub id: usize,
    // Their weight in the shared queue
    pub weight: PriorityWeight,
}

pub mod message {
    use anyhow::Result;
    use coerce::actor::message::Message;
    use plonky2x::backend::prover::ProofId;

    use super::*;

    #[derive(Debug, Clone)]
    pub struct ProveTransaction {
        pub id: Option<usize>,
        pub tx: TransactionOrReceiptId,
    }

    impl Message for ProveTransaction {
        type Result = Result<()>;
    }

    #[derive(Debug, Clone)]
    pub struct CheckProof(pub ProofId);
    impl From<ProofId> for CheckProof {
        fn from(id: ProofId) -> Self {
            Self(id)
        }
    }

    impl Message for CheckProof {
        type Result = Result<ProofResponse>;
    }

    pub struct Drain;

    impl Message for Drain {
        type Result = ();
    }

    pub struct Register(pub RegistryInfo);
}

/// An in memory queue as a placeholder until we decide on the flow
pub struct QueueManager {
    registry: HashMap<usize, RegistryInfo>,
    // TODO: decide if need parkinglot
    succinct_client: Arc<succinct::Client>,
    // TODO: persist me
    proving_queue: Arc<
        RwLock<PriorityQueue<TransactionOrReceiptIdNewtype, PriorityWeight, DefaultHashBuilder>>,
    >,
}

#[async_trait]
impl Actor for QueueManager {
    async fn started(&mut self, _ctx: &mut ActorContext) {
        tokio::spawn(self.run());
    }
}

// TODO: subscription topics

#[async_trait]
impl Handler<message::ProveTransaction> for QueueManager {
    async fn handle(
        &mut self,
        msg: message::ProveTransaction,
        _ctx: &mut ActorContext,
    ) -> <message::ProveTransaction as coerce::actor::message::Message>::Result {
        self.prove(msg).await
    }
}

#[async_trait]
impl Handler<message::CheckProof> for QueueManager {
    async fn handle(
        &mut self,
        msg: message::CheckProof,
        _ctx: &mut ActorContext,
    ) -> <message::CheckProof as coerce::actor::message::Message>::Result {
        self.check_proof(msg).await
    }
}

#[async_trait]
impl Handler<message::Drain> for QueueManager {
    async fn handle(
        &mut self,
        _msg: message::Drain,
        _ctx: &mut ActorContext,
    ) -> <message::Drain as coerce::actor::message::Message>::Result {
        Self::try_drain(self.succinct_client.clone(), self.proving_queue.clone()).await
    }
}

impl QueueManager {
    pub fn new(
        registry: HashMap<usize, RegistryInfo>,
        succinct_client: Arc<succinct::Client>,
    ) -> Self {
        log::info!("starting queue manager");
        let proving_queue = PriorityQueue::<_, _, DefaultHashBuilder>::with_default_hasher();

        Self {
            registry,
            succinct_client,
            proving_queue: Arc::new(RwLock::new(proving_queue)),
        }
    }

    async fn prove(
        &mut self,
        msg: message::ProveTransaction,
    ) -> <message::ProveTransaction as Message>::Result {
        let weight = if let Some(id) = msg.id {
            self.registry
                .get(&id)
                .ok_or_else(|| anyhow!("id not found"))?
                .weight
        } else {
            2
        };
        log::info!("Adding to proof queue {:?} with weight {weight}", msg);
        self.proving_queue.write().await.push(msg.tx.into(), weight);
        Ok(())
    }

    async fn check_proof(
        &self,
        msg: message::CheckProof,
    ) -> <message::CheckProof as Message>::Result {
        log::info!("Awaiting proof {:?}", msg.0);

        let mut poll_count = 0;
        let sleep = tokio::time::sleep(Duration::from_secs(60));
        tokio::pin!(sleep);

        loop {
            if let Ok(proof) = self.succinct_client.get_proof(&msg.0).await {
                log::info!("Got proof {:?}", proof);
                match proof.status {
                    ProofStatus::Success => {
                        break Ok(proof);
                    }
                    ProofStatus::Failure => break Ok(proof),
                    ProofStatus::Running => {}
                }
            }
            poll_count += 1;
            ensure!(poll_count < 10, "failed to get proof");
            sleep.as_mut().await;
        }
    }

    async fn try_drain(
        succinct: Arc<succinct::Client>,
        queue: Arc<
            RwLock<
                PriorityQueue<TransactionOrReceiptIdNewtype, PriorityWeight, DefaultHashBuilder>,
            >,
        >,
    ) {
        log::trace!("checking queue");
        let mut queue = queue.write().await;
        if queue.len() >= VERIFY_ID_AMT {
            let mut txs = vec![];
            for _ in 0..VERIFY_ID_AMT {
                let (req, _) = queue.pop().unwrap();
                txs.push(req.0);
            }
            let id = succinct.verify(txs, true).await.unwrap();
            // TODO: selfjobs.push(Job::CheckProof(id), 1);
        }
    }

    pub fn run(&mut self) -> tokio::task::JoinHandle<()> {
        let queue = self.proving_queue.clone();
        let succinct = self.succinct_client.clone();

        tokio::spawn(async move {
            loop {
                // TODO: housekeeping job
                tokio::select! {
                    _ = Self::try_drain(succinct.clone(), queue.clone()) => {}
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use near_light_client_rpc::TransactionOrReceiptId;
    use plonky2x::backend::prover::ProofId;
    use test_utils::{fixture, logger};
    use uuid::Uuid;

    use self::succinct::Client;
    use super::*;
    use crate::config::Config;

    async fn manager() -> QueueManager {
        let succinct_client = Client::new(&Config::test_config()).await.unwrap();
        QueueManager::new(Default::default(), Arc::new(succinct_client))
    }

    // TODO: move to integration tests
    #[ignore = "test is a live e2e test"]
    #[tokio::test]
    async fn e2e_test_verify() {
        logger();
        let mut m = manager().await;

        let fixture = fixture::<Vec<TransactionOrReceiptId>>("ids.json");
        let fixtures = fixture.iter().take(VERIFY_ID_AMT);
        for r in fixtures {
            m.prove(message::ProveTransaction {
                tx: r.clone(),
                id: None,
            })
            .await
            .unwrap();
        }
        QueueManager::try_drain(m.succinct_client, m.proving_queue).await;
    }

    #[tokio::test]
    async fn test_check_proof() {
        logger();
        let m = manager().await;

        let r = m
            .check_proof(
                ProofId(Uuid::from_str("6bb1148e-1a2a-477e-a17b-20016cdaa32d").unwrap()).into(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_weights() {
        logger();
        let mut m = manager().await;

        let high_priority_id = 1;
        let registry = vec![(
            high_priority_id,
            RegistryInfo {
                id: high_priority_id,
                weight: 5,
            },
        )]
        .into_iter()
        .collect();
        m.registry = registry;

        let fixture = fixture::<Vec<TransactionOrReceiptId>>("ids.json");
        let fixtures = fixture.iter().take(3);
        for r in fixtures {
            m.prove(message::ProveTransaction {
                tx: r.clone(),
                id: None,
            })
            .await
            .unwrap();
        }

        let mut p: Vec<TransactionOrReceiptIdNewtype> = vec![];
        for priority_tx in fixture.iter().rev().take(5) {
            m.prove(message::ProveTransaction {
                tx: priority_tx.clone(),
                id: Some(high_priority_id),
            })
            .await
            .unwrap();
            p.push(priority_tx.clone().into());
        }

        let (ret, wei) = m.proving_queue.write().await.pop().unwrap();
        assert_eq!(wei, 5);
        assert!(p.contains(&ret));

        QueueManager::try_drain(m.succinct_client, m.proving_queue).await;
    }
}

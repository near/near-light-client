use crate::{client::protocol::Protocol, config::Config};
use anyhow::{anyhow, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use flume::{Receiver, Sender};
use near_jsonrpc_client::methods::light_client_proof::RpcLightClientExecutionProofResponse as BasicProof;
use near_primitives::{types::validator_stake::ValidatorStake, views::LightClientBlockLiteView};
use near_primitives_core::{hash::CryptoHash, types::AccountId};
use serde::{Deserialize, Serialize};
use sled::Tree;
use std::{path::PathBuf, str::FromStr};
use tokio::time;

pub mod error;
pub mod protocol;
pub mod rpc;

pub const STATE_PATH: &str = "state.json";
pub type Header = LightClientBlockLiteView;

#[derive(Debug, Serialize, Deserialize)]
pub enum Proof {
    Basic(BasicProof),
    Experimental(protocol::experimental::Proof),
}

impl From<BasicProof> for Proof {
    fn from(proof: BasicProof) -> Self {
        Self::Basic(proof)
    }
}

impl From<protocol::experimental::Proof> for Proof {
    fn from(proof: protocol::experimental::Proof) -> Self {
        Self::Experimental(proof)
    }
}

pub enum ProofType {
    Transaction {
        transaction_id: CryptoHash,
        sender_id: AccountId,
    },
    Receipt {
        receipt_id: CryptoHash,
        receiver_id: AccountId,
    },
}

pub enum Message {
    Shutdown(Option<PathBuf>),
    Head {
        tx: Sender<Header>,
    },
    Archive {
        tx: Sender<Option<Header>>,
        epoch: CryptoHash,
    },
    GetProof {
        tx: Sender<Option<Proof>>,
        proof: ProofType,
    },
    ValidateProof {
        tx: Sender<bool>,
        proof: Box<Proof>,
    },
}

#[derive(Debug, Clone)]
pub struct LightClient {
    client: rpc::NearRpcClient,
    store: sled::Db,
    head: LightClientBlockLiteView,
    block_producers: Tree,
    archival_headers: Tree,
}

pub enum TreeKind {
    BlockProducers,
    ArchivalHeaders,
}

impl LightClient {
    pub fn start(mut self, mut is_fast: bool, rx: Receiver<Message>) {
        tokio::spawn(async move {
            // TODO: make configurable, currently set to ~block time
            let default_duration = time::Duration::from_secs(2);

            let mut duration = if is_fast {
                time::Duration::from_millis(100)
            } else {
                default_duration
            };

            loop {
                tokio::select! {
                    Ok(msg) = rx.recv_async() => match msg {
                        Message::Shutdown(_path) => {
                            if let Err(e) = self.shutdown().await {
                                log::error!("Failed to shutdown: {:?}", e);
                            }
                        }
                        Message::Head { tx } => {
                            if let Err(e) = tx.send_async(self.head().clone()).await {
                                log::error!("Failed to send head: {:?}", e);
                            }
                        },
                        Message::Archive { tx, epoch } => {
                            if let Err(e) = tx.send_async(self.header(epoch)).await {
                                log::error!("Failed to send archival header: {:?}", e);
                    }
                        },
                        Message::GetProof {
                            tx,
                            proof: ProofType::Transaction { transaction_id, sender_id }
                        } => {
                            if let Err(e) = tx.send_async(self.get_transaction_proof(transaction_id, sender_id).await.map(Into::into)).await {
                                log::error!("Failed to send proof: {:?}", e);
                    }
                        },
                        Message::GetProof {
                            tx, proof: ProofType::Receipt { receipt_id, receiver_id }
                        } => {
                            if let Err(e) = tx.send_async(self.get_receipt_proof(receipt_id, receiver_id).await.map(Into::into)).await {
                                log::error!("Failed to send proof: {:?}", e);
                            }
                        }
                        Message::ValidateProof { tx, proof } => {
                            if let Err(e) = tx.send_async(self.verify_proof(*proof).await).await {
                                log::error!("Failed to send validation result: {:?}", e);
                            }
                        }
                    },
                    r = self.sync() => {
                        tokio::time::sleep(duration).await;
                        match r {
                            Err(e) => log::error!("Error syncing: {:?}", e),
                            Ok(false) if is_fast => {
                                log::debug!("Slowing down sync interval to {:?}", default_duration);
                                duration = default_duration;
                                is_fast = false;
                            }
                            _ => (),
                        }
                    }
                }
            }
        });
    }

    // TODO: move to store module
    pub fn get<K: AsRef<[u8]>, T: BorshDeserialize>(&self, key: K, kind: TreeKind) -> Option<T> {
        let tree = match kind {
            TreeKind::BlockProducers => &self.block_producers,
            TreeKind::ArchivalHeaders => &self.archival_headers,
        };
        tree.get(key)
            .ok()
            .unwrap_or_default()
            .and_then(|v| BorshDeserialize::try_from_slice(&v).ok())
    }

    pub fn insert<K: AsRef<[u8]>, T: BorshSerialize>(
        &mut self,
        key: K,
        value: &T,
        kind: TreeKind,
    ) -> Result<()> {
        let tree = match kind {
            TreeKind::BlockProducers => &self.block_producers,
            TreeKind::ArchivalHeaders => &self.archival_headers,
        };
        Ok(tree
            .insert(key, BorshSerialize::try_to_vec(value)?)
            .map(|_| ())?)
    }

    pub async fn init(config: &Config) -> Result<Self> {
        let sled = sled::open(config.state_path.clone().unwrap_or(STATE_PATH.into()))
            .expect("Failed to open store");
        let client = rpc::NearRpcClient::new(config.network.clone());

        let head = sled.get("head")?;
        let block_producers = sled.open_tree("bps")?;
        let archival_headers = sled.open_tree("archive")?;

        if let Some(head) = head {
            let head: LightClientBlockLiteView =
                borsh::BorshDeserialize::try_from_slice(&head).expect("Failed to deserialize head");
            Ok(Self {
                client,
                store: sled,
                head,
                block_producers,
                archival_headers,
            })
        } else {
            let starting_head = client
                .fetch_latest_header(&CryptoHash::from_str(&config.starting_head).unwrap())
                .await
                .expect("We need a starting header");

            log::info!("Got starting head: {:?}", starting_head.inner_lite.height);

            block_producers.insert(
                starting_head.inner_lite.epoch_id,
                borsh::to_vec(&starting_head.next_bps.clone().unwrap())?,
            )?;

            Ok(Self {
                client,
                store: sled,
                head: LightClientBlockLiteView {
                    prev_block_hash: starting_head.prev_block_hash,
                    inner_rest_hash: starting_head.inner_rest_hash,
                    inner_lite: starting_head.inner_lite,
                },
                block_producers,
                archival_headers,
            })
        }
    }

    pub async fn sync(&mut self) -> Result<bool> {
        log::trace!("Current head: {:#?}", self.head.inner_lite);

        let next_header = self
            .client
            .fetch_latest_header(
                &CryptoHash::from_str(&format!("{}", self.head.hash()))
                    .map_err(|e| anyhow!("Failed to parse hash: {:?}", e))?,
            )
            .await
            .ok_or_else(|| anyhow!("Failed to fetch latest header"))?;
        log::trace!("Got new header: {:#?}", next_header.inner_lite);

        let bps = self
            .get::<_, Vec<ValidatorStake>>(&self.head.inner_lite.epoch_id, TreeKind::BlockProducers)
            .ok_or_else(|| anyhow!("Failed to get block producers"))?;

        let synced = Protocol::sync(&self.head, &bps, next_header)?;

        if let Some((epoch, next_bps)) = synced.next_bps {
            log::debug!("storing next bps[{:?}]", epoch);
            self.insert(epoch, &next_bps, TreeKind::BlockProducers)?;
        }

        self.insert(
            self.head.inner_lite.epoch_id,
            &synced.new_head,
            TreeKind::ArchivalHeaders,
        )?;
        self.head = synced.new_head;
        self.store.insert("head", self.head.try_to_vec()?)?;

        Ok(true)
    }

    fn head(&self) -> &Header {
        &self.head
    }

    fn header(&self, epoch: CryptoHash) -> Option<Header> {
        self.get::<_, LightClientBlockLiteView>(&epoch, TreeKind::ArchivalHeaders)
    }

    // TODO: memoize these in a real cache
    pub async fn get_transaction_proof(
        &mut self,
        transaction_id: CryptoHash,
        sender_id: AccountId,
    ) -> Option<BasicProof> {
        // TODO: we need much more logic here for headers in different epochs & the head
        // since there are race conditions when we come to validate the proof header, we'd need to short-cache the proof validation
        let last_verified_hash = self.head.hash();

        self.client
            .fetch_light_client_tx_proof(transaction_id, sender_id, last_verified_hash)
            .await
            .map(|proof| {
                if let Err(e) = self.insert(
                    proof.outcome_proof.block_hash,
                    &self.head.clone(),
                    TreeKind::ArchivalHeaders,
                ) {
                    log::warn!("Failed to insert archival header: {:?}", e)
                }
                proof
            })
    }

    pub async fn get_receipt_proof(
        &mut self,
        receipt_id: CryptoHash,
        receiver_id: AccountId,
    ) -> Option<BasicProof> {
        let last_verified_hash = self.head.hash();
        self.client
            .fetch_light_client_receipt_proof(receipt_id, receiver_id, last_verified_hash)
            .await
            .map(|proof| {
                if let Err(e) = self.insert(
                    proof.outcome_proof.block_hash,
                    &self.head.clone(),
                    TreeKind::ArchivalHeaders,
                ) {
                    log::warn!("Failed to insert archival header: {:?}", e)
                }
                proof
            })
    }

    pub async fn verify_proof(&mut self, p: Proof) -> bool {
        // TODO: this is a hack
        let archive = match &p {
            Proof::Basic(p) => self.get::<_, LightClientBlockLiteView>(
                p.outcome_proof.block_hash,
                TreeKind::ArchivalHeaders,
            ),
            Proof::Experimental(_) => None,
        };
        Protocol::inclusion_proof_verify(&self.head, archive.as_ref(), p)
            .inspect_err(|e| log::warn!("Failed to verify proof: {:?}", e))
            .unwrap_or_default()
    }

    pub async fn shutdown(&self) -> Result<()> {
        log::info!("Shutting down light client");
        if let Err(e) = self.store.insert("head", self.head.try_to_vec()?) {
            log::warn!("Failed to insert head: {:?}", e)
        }
        log::info!("Head: {:?}", self.head.inner_lite.height);
        self.store.flush_async().await?;
        log::info!("Flushed store");
        todo!("Deliberate panic here, need to make this graceful");
    }
}

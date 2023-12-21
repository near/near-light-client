use crate::{client::error::Error, config::Config};
use borsh::{BorshDeserialize, BorshSerialize};
use flume::{Receiver, Sender};
use near_crypto::Signature;
use near_jsonrpc_client::methods::light_client_proof::RpcLightClientExecutionProofResponse;
use near_primitives::{
    block_header::{ApprovalInner, BlockHeaderInnerLite},
    merkle::{self},
    views::{
        validator_stake_view::ValidatorStakeView, BlockHeaderInnerLiteView,
        LightClientBlockLiteView, LightClientBlockView,
    },
};
use near_primitives_core::{
    hash::CryptoHash,
    types::{AccountId, BlockHeight},
};
use sled::Tree;
use std::{path::PathBuf, str::FromStr};
use tokio::time;

pub mod error;
pub mod proof;
pub mod rpc;

pub type Header = LightClientBlockLiteView;
pub type Proof = RpcLightClientExecutionProofResponse;

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

pub const STATE_PATH: &str = "state.json";

macro_rules! cvec {
	($($x:expr),*) => {
		{
			let mut temp_vec = Vec::new();
			$(
				temp_vec.extend_from_slice(&$x);
			)*
			temp_vec
		}
	};
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
                            if let Err(e) = tx.send_async(self.get_transaction_proof(transaction_id, sender_id).await).await {
                                log::error!("Failed to send proof: {:?}", e);
                    }
                        },
                        Message::GetProof {
                            tx, proof: ProofType::Receipt { receipt_id, receiver_id }
                        } => {
                            if let Err(e) = tx.send_async(self.get_receipt_proof(receipt_id, receiver_id).await).await {
                                log::error!("Failed to send proof: {:?}", e);
                            }
                        }
                        Message::ValidateProof { tx, proof } => {
                            if let Err(e) = tx.send_async(self.verify_proof(*proof).await).await {
                                log::error!("Failed to send validation result: {:?}", e);
                            }
                        }
                    },
                    // r = self.sync() => {
                    //     tokio::time::sleep(duration).await;
                    //     match r {
                    //         Err(e) => log::error!("Error syncing: {:?}", e),
                    //         Ok(false) if is_fast => {
                    //             log::debug!("Slowing down sync interval to {:?}", default_duration);
                    //             duration = default_duration;
                    //             is_fast = false;
                    //         }
                    //         _ => (),
                    //     }
                    // }
                }
            }
        });
    }
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
    ) -> anyhow::Result<()> {
        let tree = match kind {
            TreeKind::BlockProducers => &self.block_producers,
            TreeKind::ArchivalHeaders => &self.archival_headers,
        };
        Ok(tree
            .insert(key, BorshSerialize::try_to_vec(value)?)
            .map(|_| ())?)
    }

    pub async fn init(config: &Config) -> anyhow::Result<Self> {
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

    // TODO: Try to optimise
    // TODO: Remove mutability return
    pub async fn sync(&mut self) -> anyhow::Result<bool> {
        let mut new_state: LightClientState = self.head.clone().into();
        log::trace!("Current head: {:#?}", new_state.head.inner_lite);

        let new_header = self
            .client
            .fetch_latest_header(
                &CryptoHash::from_str(&format!("{}", new_state.head.hash()))
                    .map_err(|e| anyhow::anyhow!("Failed to parse hash: {:?}", e))?,
            )
            .await;

        if let Some(new_header) = new_header {
            log::trace!("Got new header: {:#?}", new_header.inner_lite);
            let validated = self
                .get::<_, Vec<ValidatorStakeView>>(
                    &new_state.head.inner_lite.epoch_id,
                    TreeKind::BlockProducers,
                )
                .and_then(|bps| {
                    new_state
                        .validate_and_update_head(&new_header, bps.clone())
                        .map_err(|x| log::trace!("Failed to validate header: {:?}", x))
                        .ok()
                });

            if validated.is_some() {
                log::debug!("Validated new header: {:?}", new_header.inner_lite.height);
                if let Some((epoch, next_bps)) = new_state.next_bps {
                    log::debug!("storing next bps[{:?}]", epoch);
                    self.insert(epoch, &next_bps, TreeKind::BlockProducers)?;
                }

                self.insert(
                    self.head.inner_lite.epoch_id,
                    &self.head.clone(),
                    TreeKind::ArchivalHeaders,
                )?;
                self.head = new_state.head;
                self.store.insert("head", self.head.try_to_vec()?)?;
                Ok(true)
            } else {
                log::debug!("New header is invalid");
                Ok(false)
            }
        } else {
            log::trace!("No new header found");
            Ok(false)
        }
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
    ) -> Option<Proof> {
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
    ) -> Option<Proof> {
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

    // TODO: no panic
    pub async fn verify_proof(&mut self, body: Proof) -> bool {
        let block_hash = body.block_header_lite.hash();
        assert_eq!(block_hash, body.outcome_proof.block_hash);

        let outcome_root = merkle::compute_root_from_path(
            &body.outcome_proof.proof,
            CryptoHash::hash_borsh(body.outcome_proof.to_hashes()),
        );

        let outcome_root =
            merkle::compute_root_from_path_and_item(&body.outcome_root_proof, outcome_root);
        log::debug!("outcome_root: {:?}", outcome_root);

        let outcome_root_matches = outcome_root == body.block_header_lite.inner_lite.outcome_root;

        let mut block_verified = merkle::verify_hash(
            self.head.inner_lite.block_merkle_root,
            &body.block_proof,
            block_hash,
        );

        // Functionality to cover race conditions between previously synced heads since the current head may of changed
        // since the proof was generated
        // FIXME: bug here if the same proof is requested
        if !block_verified {
            if let Some(r) = self
                .get::<_, LightClientBlockLiteView>(
                    &body.outcome_proof.block_hash,
                    TreeKind::ArchivalHeaders,
                )
                .and_then(|archive| {
                    log::debug!(
                        "Trying to verify against archival header: {:?}",
                        archive.inner_lite.height
                    );
                    if merkle::verify_hash(
                        archive.inner_lite.block_merkle_root,
                        &body.block_proof,
                        block_hash,
                    ) {
                        log::debug!("Verified against archival header");
                        block_verified = true;
                        Some(archive.inner_lite.block_merkle_root)
                    } else {
                        None
                    }
                })
            {
                if let Err(e) = self.archival_headers.remove(r) {
                    log::warn!("Failed to remove archival header: {:?}", e)
                }
            }
        }

        log::debug!(
            "shard outcome included: {:?}, block included: {:?}",
            outcome_root_matches,
            block_verified
        );
        outcome_root_matches && block_verified
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
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

#[derive(Debug, Clone)]
pub struct LightClientState {
    pub head: LightClientBlockLiteView,
    pub next_bps: Option<(CryptoHash, Vec<ValidatorStakeView>)>,
}

impl From<LightClientBlockLiteView> for LightClientState {
    fn from(head: LightClientBlockLiteView) -> Self {
        Self {
            head,
            next_bps: None,
        }
    }
}

impl LightClientState {
    fn inner_lite_hash(ilv: &BlockHeaderInnerLiteView) -> CryptoHash {
        let full_inner: BlockHeaderInnerLite = ilv.clone().into();
        CryptoHash::hash_borsh(full_inner)
    }

    fn calculate_current_block_hash(block_view: &LightClientBlockView) -> CryptoHash {
        let inner_light_hash = Self::inner_lite_hash(&block_view.inner_lite);
        CryptoHash::hash_bytes(&cvec!(
            CryptoHash::hash_bytes(&cvec!(inner_light_hash.0, block_view.inner_rest_hash.0))
                .as_bytes()
                .as_ref(),
            block_view.prev_block_hash.as_bytes().as_ref()
        ))
    }

    fn next_block_hash(
        &self,
        current_block_hash: &CryptoHash,
        block_view: &LightClientBlockView,
    ) -> CryptoHash {
        CryptoHash::hash_bytes(&cvec!(
            block_view.next_block_inner_hash.0,
            current_block_hash.0
        ))
    }

    fn reconstruct_light_client_block_view_fields(
        &mut self,
        block_view: &LightClientBlockView,
    ) -> ([u8; 32], [u8; 32], Vec<u8>) {
        let current_block_hash = Self::calculate_current_block_hash(block_view);
        let next_block_hash: CryptoHash = self.next_block_hash(&current_block_hash, block_view);

        let endorsement = ApprovalInner::Endorsement(next_block_hash);

        let approval_message = cvec!(
            endorsement.try_to_vec().unwrap()[..],
            (block_view.inner_lite.height + 2).to_le_bytes()[..]
        );

        log::debug!("Current block hash: {}", current_block_hash);
        log::debug!("Next block hash: {}", next_block_hash);
        log::debug!("Approval message: {:?}", approval_message);
        (
            *current_block_hash.as_bytes(),
            next_block_hash.into(),
            approval_message,
        )
    }

    pub fn ensure_not_already_verified(
        head: &LightClientBlockLiteView,
        block_height: &BlockHeight,
    ) -> Result<(), Error> {
        if block_height <= &head.inner_lite.height {
            Err(Error::BlockAlreadyVerified)
        } else {
            Ok(())
        }
    }

    pub fn ensure_epoch_is_current_or_next(
        head: &LightClientBlockLiteView,
        epoch_id: &CryptoHash,
    ) -> Result<(), Error> {
        if ![head.inner_lite.epoch_id, head.inner_lite.next_epoch_id].contains(epoch_id) {
            log::debug!("Block is not in the current or next epoch");
            Err(Error::BlockNotCurrentOrNextEpoch)
        } else {
            Ok(())
        }
    }

    pub fn ensure_if_next_epoch_contains_next_bps(
        head: &LightClientBlockLiteView,
        epoch_id: &CryptoHash,
        next_bps: &Option<Vec<ValidatorStakeView>>,
    ) -> Result<(), Error> {
        if &head.inner_lite.next_epoch_id == epoch_id && next_bps.is_none() {
            log::debug!("Block is in the next epoch but no new set");
            Err(Error::BlockMissingNextBps)
        } else {
            Ok(())
        }
    }

    pub fn validate_signatures(
        signatures: &[Option<Signature>],
        epoch_block_producers: Vec<ValidatorStakeView>,
        approval_message: &[u8],
    ) -> Result<(u128, u128), Error> {
        let mut total_stake = 0;
        let mut approved_stake = 0;

        for (maybe_signature, block_producer) in signatures.iter().zip(epoch_block_producers.iter())
        {
            let vs = block_producer.clone().into_validator_stake();
            let bps_stake = vs.stake();
            let bps_pk = vs.public_key();

            total_stake += bps_stake;

            if let Some(signature) = maybe_signature {
                log::trace!(
                    "Checking if signature {} and message {:?} was signed by {}",
                    signature,
                    approval_message,
                    bps_pk
                );
                if !signature.verify(approval_message, bps_pk) {
                    log::debug!("Signature is invalid");
                    return Err(Error::SignatureInvalid);
                }
                approved_stake += bps_stake;
            }
        }
        Ok((total_stake, approved_stake))
    }

    pub fn ensure_stake_is_sufficient(
        total_stake: &u128,
        approved_stake: &u128,
    ) -> Result<(), Error> {
        let threshold = total_stake * 2 / 3;

        if approved_stake <= &threshold {
            log::debug!("Not enough stake approved");
            Err(Error::NotEnoughApprovedStake)
        } else {
            Ok(())
        }
    }

    pub fn ensure_next_bps_is_valid(
        expected_hash: &CryptoHash,
        next_bps: &Option<Vec<ValidatorStakeView>>,
    ) -> Result<Vec<ValidatorStakeView>, Error> {
        if let Some(next_bps) = next_bps {
            let next_bps_hash = CryptoHash::hash_borsh(next_bps);
            if &next_bps_hash != expected_hash {
                log::warn!("Next block producers hash is invalid");
                return Err(Error::NextBpsInvalid);
            }

            Ok(next_bps.clone())
        } else {
            // No new bps
            Ok(Default::default())
        }
    }

    pub fn validate_and_update_head(
        &mut self,
        block_view: &LightClientBlockView,
        epoch_block_producers: Vec<ValidatorStakeView>,
    ) -> Result<(), Error> {
        let (_, _, approval_message) = self.reconstruct_light_client_block_view_fields(block_view);

        Self::ensure_not_already_verified(&self.head, &block_view.inner_lite.height)?;
        Self::ensure_epoch_is_current_or_next(&self.head, &block_view.inner_lite.epoch_id)?;
        Self::ensure_if_next_epoch_contains_next_bps(
            &self.head,
            &block_view.inner_lite.epoch_id,
            &block_view.next_bps,
        )?;
        let (total_stake, approved_stake) = Self::validate_signatures(
            &block_view.approvals_after_next,
            epoch_block_producers,
            &approval_message,
        )?;
        Self::ensure_stake_is_sufficient(&total_stake, &approved_stake)?;

        if let Ok(next_bps) = Self::ensure_next_bps_is_valid(
            &block_view.inner_lite.next_bp_hash,
            &block_view.next_bps,
        ) {
            log::trace!("Setting next bps[{:?}]", self.head.inner_lite.next_epoch_id);
            self.next_bps = Some((self.head.inner_lite.next_epoch_id, next_bps));
        }

        let prev_head = self.head.inner_lite.height;
        self.head = LightClientBlockLiteView {
            prev_block_hash: block_view.prev_block_hash,
            inner_rest_hash: block_view.inner_rest_hash,
            inner_lite: block_view.inner_lite.clone(),
        };
        let new_head = self.head.inner_lite.height;
        log::debug!("prev/current head: {}/{}", prev_head, new_head);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;
    use near_primitives::merkle::compute_root_from_path;
    use serde_json::{self, json};

    fn fixture(file: &str) -> LightClientBlockView {
        serde_json::from_reader(std::fs::File::open(file).unwrap()).unwrap()
    }

    fn get_previous() -> LightClientBlockView {
        fixture("fixtures/2_previous_epoch.json")
    }
    fn get_previous_previous() -> LightClientBlockView {
        fixture("fixtures/3_previous_epoch.json")
    }

    fn get_current() -> LightClientBlockView {
        fixture("fixtures/1_current_epoch.json")
    }

    fn get_epochs() -> Vec<(u32, LightClientBlockView, CryptoHash)> {
        vec![
            (
                1,
                get_previous_previous(),
                CryptoHash::from_str("B35Jn6mLXACRcsf6PATMixqgzqJZd71JaNh1LScJjFuJ").unwrap(),
            ),
            (
                2,
                get_previous(),
                CryptoHash::from_str("Doy7Y7aVMgN8YhdAseGBMHNmYoqzWsXszqJ7MFLNMcQ7").unwrap(),
            ), // Doy7Y7aVMgN8YhdAseGBMHNmYoqzWsXszqJ7MFLNMcQ7
            (
                3,
                get_current(),
                CryptoHash::from_str("3tyxRRBgbYTo5DYd1LpX3EZtEiRYbDAAji6kcsf9QRge").unwrap(),
            ), // 3tyxRRBgbYTo5DYd1LpX3EZtEiRYbDAAji6kcsf9QRge
        ]
    }
    fn view_to_lite_view(h: LightClientBlockView) -> LightClientBlockLiteView {
        LightClientBlockLiteView {
            prev_block_hash: h.prev_block_hash,
            inner_rest_hash: h.inner_rest_hash,
            inner_lite: h.inner_lite,
        }
    }

    #[test]
    fn test_headers() {
        let headers_by_epoch = get_epochs();
        let next_epoch_id = headers_by_epoch[1].1.inner_lite.epoch_id.clone();

        let mut state = LightClientState {
            head: view_to_lite_view(headers_by_epoch[0].1.clone()),
            next_bps: Some((
                next_epoch_id,
                headers_by_epoch[0]
                    .1
                    .next_bps
                    .clone()
                    .unwrap()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )),
        };

        let (current, _, approval_message) =
            state.reconstruct_light_client_block_view_fields(&headers_by_epoch[1].1);
        assert_eq!(current, headers_by_epoch[1].2 .0);

        let signature = headers_by_epoch[1].1.approvals_after_next[0]
            .clone()
            .unwrap();
        assert!(signature.verify(
            &approval_message,
            get_previous_previous().next_bps.unwrap()[0]
                .clone()
                .into_validator_stake()
                .public_key()
        ));
    }

    fn bootstrap_state() -> (LightClientState, LightClientBlockView) {
        let headers_by_epoch = get_epochs();
        let next_epoch_id = headers_by_epoch[1].1.inner_lite.epoch_id.clone();
        let new_header = headers_by_epoch[1].1.clone();

        (
            LightClientState {
                head: view_to_lite_view(headers_by_epoch[0].1.clone()),
                next_bps: Some((
                    next_epoch_id,
                    headers_by_epoch[0]
                        .1
                        .next_bps
                        .clone()
                        .unwrap()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                )),
            },
            new_header,
        )
    }
    #[test]
    fn test_blackbox_validate() {
        pretty_env_logger::try_init().ok();
        let headers_by_epoch = get_epochs();

        let (mut state, next_header) = bootstrap_state();

        state
            .validate_and_update_head(
                &next_header,
                headers_by_epoch[0].1.next_bps.clone().unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn test_validate_already_verified() {
        pretty_env_logger::try_init().ok();
        assert_eq!(
            LightClientState::ensure_not_already_verified(
                &bootstrap_state().0.head,
                &BlockHeight::MIN
            ),
            Err(Error::BlockAlreadyVerified)
        );
    }
    #[test]
    fn test_validate_bad_epoch() {
        pretty_env_logger::try_init().ok();
        assert_eq!(
            LightClientState::ensure_epoch_is_current_or_next(
                &bootstrap_state().0.head,
                &CryptoHash::hash_bytes(b"bogus hash")
            ),
            Err(Error::BlockNotCurrentOrNextEpoch)
        );
    }

    #[test]
    fn test_next_epoch_bps() {
        pretty_env_logger::try_init().ok();

        let (state, mut next_block) = bootstrap_state();
        next_block.next_bps = None;

        assert_eq!(
            LightClientState::ensure_if_next_epoch_contains_next_bps(
                &state.head,
                &next_block.inner_lite.epoch_id,
                &next_block.next_bps
            ),
            Err(Error::BlockMissingNextBps)
        );
    }

    #[test]
    fn test_next_invalid_signature() {
        pretty_env_logger::try_init().ok();
        let (_, next_block) = bootstrap_state();
        let headers_by_epoch = get_epochs();

        assert_eq!(
            LightClientState::validate_signatures(
                &next_block.approvals_after_next,
                headers_by_epoch[0].1.next_bps.clone().unwrap(),
                &b"bogus approval message"[..]
            ),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn test_next_invalid_signatures_no_approved_stake() {
        pretty_env_logger::try_init().ok();

        let (mut state, mut next_block) = bootstrap_state();
        let headers_by_epoch = get_epochs();

        let (_, _, approval_message) =
            state.reconstruct_light_client_block_view_fields(&next_block);

        next_block.approvals_after_next = next_block
            .approvals_after_next
            .iter()
            .cloned()
            .map(|_| None)
            .collect();

        let (total_stake, approved_stake) = LightClientState::validate_signatures(
            &next_block.approvals_after_next,
            headers_by_epoch[0].1.next_bps.clone().unwrap(),
            &approval_message,
        )
        .unwrap();

        assert_eq!(
            (total_stake, approved_stake),
            (512915271547861520119028536348929, 0)
        );
    }

    #[test]
    fn test_next_invalid_signatures_stake_isnt_sufficient() {
        pretty_env_logger::try_init().ok();

        let (mut state, next_block) = bootstrap_state();
        let headers_by_epoch = get_epochs();

        let (_, _, approval_message) =
            state.reconstruct_light_client_block_view_fields(&next_block);

        let (total_stake, approved_stake) = LightClientState::validate_signatures(
            &next_block.approvals_after_next,
            headers_by_epoch[0].1.next_bps.clone().unwrap(),
            &approval_message,
        )
        .unwrap();

        assert_eq!(
            (total_stake, approved_stake),
            (
                512915271547861520119028536348929,
                345140782903867823005444871054881
            )
        );

        assert!(
            LightClientState::ensure_stake_is_sufficient(&total_stake, &approved_stake).is_ok()
        );

        assert_eq!(
            LightClientState::ensure_stake_is_sufficient(
                &total_stake,
                &((total_stake * 2) / 3 - 1)
            ),
            Err(Error::NotEnoughApprovedStake)
        );
    }

    #[test]
    fn test_next_invalid_bps_stake() {
        let (state, next_block) = bootstrap_state();

        assert_eq!(
            LightClientState::ensure_if_next_epoch_contains_next_bps(
                &state.head,
                &next_block.inner_lite.epoch_id,
                &None
            ),
            Err(Error::BlockMissingNextBps)
        );
    }

    #[test]
    fn test_next_bps_invalid_hash() {
        pretty_env_logger::try_init().ok();

        let (_, next_header) = bootstrap_state();

        assert_eq!(
            LightClientState::ensure_next_bps_is_valid(
                &CryptoHash::hash_borsh(b"invalid"),
                &next_header.next_bps
            ),
            Err(Error::NextBpsInvalid)
        );
    }

    #[test]
    fn test_next_bps() {
        pretty_env_logger::try_init().ok();

        let (_, next_block) = bootstrap_state();

        assert_eq!(
            LightClientState::ensure_next_bps_is_valid(
                &next_block.inner_lite.next_bp_hash,
                &next_block.next_bps
            )
            .unwrap(),
            next_block.next_bps.unwrap()
        );
    }

    #[test]
    fn test_next_bps_noop() {
        pretty_env_logger::try_init().ok();

        let (_, next_block) = bootstrap_state();

        assert_eq!(
            LightClientState::ensure_next_bps_is_valid(&next_block.inner_lite.next_bp_hash, &None)
                .unwrap(),
            vec![]
        );
    }

    #[test]
    fn test_can_create_current_hash() {
        let file = "fixtures/well_known_header.json";
        let prev_hash =
            CryptoHash::from_str("BUcVEkMq3DcZzDGgeh1sb7FFuD86XYcXpEt25Cf34LuP").unwrap();
        let well_known_header_view: BlockHeaderInnerLiteView =
            serde_json::from_reader(std::fs::File::open(file).unwrap()).unwrap();

        let inner_light_hash = LightClientState::inner_lite_hash(&well_known_header_view);

        // Inner rest hashing
        for (inner_rest, expected) in vec![
            (
                "FaU2VzTNqxfouDtkQWcmrmU2UdvtSES3rQuccnZMtWAC",
                "3ckGjcedZiN3RnvfiuEN83BtudDTVa9Pub4yZ8R737qt",
            ),
            (
                "BEqJyfEYNNrKmhHToZTvbeYqVjoqSe2w2uTMMT9KDaqb",
                "Hezx56VTH815G6JTzWqJ7iuWxdR9X4ZqGwteaDF8q2z",
            ),
            (
                "7Kg3Uqeg7XSoQ7qXbed5JUR48YE49EgLiuqBTRuiDq6j",
                "Finjr87adnUqpFHVXbmAWiVAY12EA9G4DfUw27XYHox",
            ),
        ] {
            let inner_rest_hash = CryptoHash::from_str(inner_rest).unwrap();
            let expected = CryptoHash::from_str(expected).unwrap();

            let inner_hash = CryptoHash::hash_bytes(&cvec!(inner_light_hash.0, inner_rest_hash.0))
                .0
                .to_vec();
            let current_hash =
                CryptoHash::hash_bytes(&cvec!(inner_hash, prev_hash.as_bytes().to_vec()));
            assert_eq!(current_hash, expected);
        }
    }

    #[test]
    fn test_can_recreate_current_block_hash() {
        let file = "fixtures/well_known_header.json";
        let prev_hash =
            CryptoHash::from_str("BUcVEkMq3DcZzDGgeh1sb7FFuD86XYcXpEt25Cf34LuP").unwrap();
        let well_known_header_view: BlockHeaderInnerLiteView =
            serde_json::from_reader(std::fs::File::open(file).unwrap()).unwrap();

        // Inner rest hashing
        for (inner_rest, expected) in vec![
            (
                "FaU2VzTNqxfouDtkQWcmrmU2UdvtSES3rQuccnZMtWAC",
                "3ckGjcedZiN3RnvfiuEN83BtudDTVa9Pub4yZ8R737qt",
            ),
            (
                "BEqJyfEYNNrKmhHToZTvbeYqVjoqSe2w2uTMMT9KDaqb",
                "Hezx56VTH815G6JTzWqJ7iuWxdR9X4ZqGwteaDF8q2z",
            ),
            (
                "7Kg3Uqeg7XSoQ7qXbed5JUR48YE49EgLiuqBTRuiDq6j",
                "Finjr87adnUqpFHVXbmAWiVAY12EA9G4DfUw27XYHox",
            ),
        ] {
            let inner_rest_hash = CryptoHash::from_str(inner_rest).unwrap();
            let expected = CryptoHash::from_str(expected).unwrap();

            let view = LightClientBlockView {
                inner_lite: well_known_header_view.clone(),
                inner_rest_hash,
                prev_block_hash: prev_hash,
                // Not needed for this test
                approvals_after_next: vec![],
                next_bps: None,
                next_block_inner_hash: CryptoHash::default(),
            };

            let current_hash = LightClientState::calculate_current_block_hash(&view);
            assert_eq!(current_hash, expected);
        }
    }

    #[test]
    fn test_shard_outcome_root() {
        pretty_env_logger::try_init().ok();
        let req = r#"{"outcome_proof":{"proof":[],"block_hash":"5CY72FinjVV2Hd5zRikYYMaKh67pftXJsw8vwRXAUAQF","id":"9UhBumQ3eEmPH5ALc3NwiDCQfDrFakteRD7rHE9CfZ32","outcome":{"logs":[],"receipt_ids":["2mrt6jXKwWzkGrhucAtSc8R3mjrhkwCjnqVckPdCMEDo"],"gas_burnt":2434069818500,"tokens_burnt":"243406981850000000000","executor_id":"datayalla.testnet","status":{"SuccessReceiptId":"2mrt6jXKwWzkGrhucAtSc8R3mjrhkwCjnqVckPdCMEDo"},"metadata":{"version":1,"gas_profile":null}}},"outcome_root_proof":[{"hash":"9f7YjLvzvSspJMMJ3DDTrFaEyPQ5qFqQDNoWzAbSTjTy","direction":"Right"},{"hash":"67ZxFmzWXbWJSyi7Wp9FTSbbJx2nMr7wSuW3EP1cJm4K","direction":"Left"}],"block_header_lite":{"prev_block_hash":"AEnTyGRrk2roQkYSWoqYhzkbp5SWWJtCd71ZYyj1P26i","inner_rest_hash":"G25j8jSWRyrXV317cPC3qYA4SyJWXsBfErjhBYQkxw5A","inner_lite":{"height":134481525,"epoch_id":"4tBzDozzGED3QiCRURfViVuyJy5ikaN9dVH7m2MYkTyw","next_epoch_id":"9gYJSiT3TQbKbwui5bdbzBA9PCMSSfiffWhBdMtcasm2","prev_state_root":"EwkRecSP8GRvaxL7ynCEoHhsL1ksU6FsHVLCevcccF5q","outcome_root":"8Eu5qpDUMpW5nbmTrTKmDH2VYqFEHTKPETSTpPoyGoGc","timestamp":1691615068679535000,"timestamp_nanosec":"1691615068679535094","next_bp_hash":"8LCFsP6LeueT4X3PEni9CMvH7maDYpBtfApWZdXmagss","block_merkle_root":"583vb6csYnczHyt5z6Msm4LzzGkceTZHdvXjC8vcWeGK"}},"block_proof":[{"hash":"AEnTyGRrk2roQkYSWoqYhzkbp5SWWJtCd71ZYyj1P26i","direction":"Left"},{"hash":"HgZaHXpb5zs4rxUQTeW69XBNLBJoo4sz2YEDh7aFnMpC","direction":"Left"},{"hash":"EYNXYsnESQkXo7B27a9xu6YgbDSyynNcByW5Q2SqAaKH","direction":"Right"},{"hash":"AbKbsD7snoSnmzAtwNqXLBT5sm7bZr48GCCLSdksFuzi","direction":"Left"},{"hash":"7KKmS7n3MtCfv7UqciidJ24Abqsk8m85jVQTh94KTjYS","direction":"Left"},{"hash":"5nKA1HCZMJbdCccZ16abZGEng4sMoZhKez74rcCFjnhL","direction":"Left"},{"hash":"BupagAycSLD7v42ksgMKJFiuCzCdZ6ksrGLwukw7Vfe3","direction":"Right"},{"hash":"D6v37P4kcVJh8N9bV417eqJoyMeQbuZ743oNsbKxsU7z","direction":"Right"},{"hash":"8sWxxbe1rdquP5VdYfQbw1UvtcXDRansJYJV5ySzyow4","direction":"Right"},{"hash":"CmKVKWRqEqi4UaeKKYXpPSesYqdQYwHQM3E4xLKEUAj8","direction":"Left"},{"hash":"3TvjFzVyPBvPpph5zL6VCASLCxdNeiKV6foPwUpAGqRv","direction":"Left"},{"hash":"AnzSG9f91ePS6L6ii3eAkocp4iKjp6wjzSwWsDYWLnMX","direction":"Right"},{"hash":"FYVJDL4T6c87An3pdeBvntB68NzpcPtpvLP6ifjxxNkr","direction":"Left"},{"hash":"2YMF6KE8XTz7Axj3uyAoFbZisWej9Xo8mxgVtauWCZaV","direction":"Left"},{"hash":"4BHtLcxqNfWSneBdW76qsd8om8Gjg58Qw5BX8PHz93hf","direction":"Left"},{"hash":"7G3QUT7NQSHyXNQyzm8dsaYrFk5LGhYaG7aVafKAekyG","direction":"Left"},{"hash":"3XaMNnvnX69gGqBJX43Na1bSTJ4VUe7z6h5ZYJsaSZZR","direction":"Left"},{"hash":"FKu7GtfviPioyAGXGZLBVTJeG7KY5BxGwuL447oAZxiL","direction":"Right"},{"hash":"BePd7DPKUQnGtnSds5fMJGBUwHGxSNBpaNLwceJGUcJX","direction":"Left"},{"hash":"2BVKWMd9pXZTEyE9D3KL52hAWAyMrXj1NqutamyurrY1","direction":"Left"},{"hash":"EWavHKhwQiT8ApnXvybvc9bFY6aJYJWqBhcrZpubKXtA","direction":"Left"},{"hash":"83Fsd3sdx5tsJkb6maBE1yViKiqbWCCNfJ4XZRsKnRZD","direction":"Left"},{"hash":"AaT9jQmUvVpgDHdFkLR2XctaUVdTti49enmtbT5hsoyL","direction":"Left"}]}"#;
        let body: RpcLightClientExecutionProofResponse = serde_json::from_str(req).unwrap();
        // shard_outcome_root = compute_root(sha256(borsh(execution_outcome)), outcome_proof.proof)

        println!(
            "Verifying light client proof for txn id: {:?}",
            body.outcome_proof.id
        );

        let outcome_hash = CryptoHash::hash_borsh(&body.outcome_proof.to_hashes());
        println!("Hash of the outcome is: {:?}", outcome_hash);

        let shard_outcome_root = compute_root_from_path(&body.outcome_proof.proof, outcome_hash);
        println!("Shard outcome root is: {:?}", shard_outcome_root);
        let block_outcome_root = compute_root_from_path(
            &body.outcome_root_proof,
            CryptoHash::hash_borsh(shard_outcome_root),
        );
        println!("Block outcome root is: {:?}", block_outcome_root);

        let expected_shard_outcome_root =
            CryptoHash::from_str("AC7P5WhmY1kFaL7ZWpCToPcQpH4kuxBnzCx53BSWDzY7").unwrap();
        assert_eq!(shard_outcome_root, expected_shard_outcome_root);
    }

    #[test]
    fn test_root() {
        let root = "WWrLWbWHwSmjtTn5oBZPYgRCuCYn6fkYVa4yhPWNK4L";

        let old_block_hash = "7xTJs2wYhLcWKsT2Vcf4HPcXVdKKxTAPFTphhEhf3AxW";
        let old_proof = json!([
        {
            "direction": "Left",
            "hash": "GCvcb8M3qHWtvmSdEZFUWcTd6TwifECQZbV932S3AJzj"
        },
        {
            "direction": "Left",
            "hash": "RYJXmEszufH799Rzsu669aUo96YCPqN8K93DWVYoj7A"
        },
        {
            "direction": "Left",
            "hash": "C1epDr3Zy7sBLJcrwN1q8JNqCRbL9ZwGXdUdudMkKgZK"
        },
        {
            "direction": "Right",
            "hash": "4S5gtNEiMPPLzSZ2HKQr62PEFa2sFKyGWZ3Hzm3wmmZv"
        },
        {
            "direction": "Left",
            "hash": "3xo4CBANUZFc8bpX1X4cZHd9uEMJtxagxYjq5N9XGkF6"
        },
        {
            "direction": "Right",
            "hash": "2ZecgrRDh4i7CcxHsS6NMRTMvd5NCxo3Mjx8prho7Gd8"
        },
        {
            "direction": "Left",
            "hash": "51BaXGWzouQPb1dme26UmDZQ4PAJqUmcU3utoyKwQs3Z"
        },
        {
            "direction": "Left",
            "hash": "3R2JTnndX74J1zYCnWPM4JdKvTrMwW8Tj3N7tcCmMPr5"
        },
        {
            "direction": "Right",
            "hash": "74pTjaUkKY42tqDSy3wjRmH8X7bkjoiQiQ4AibnvShF2"
        },
        {
            "direction": "Right",
            "hash": "FVKmSZx11uW5itjGZf6B3aCs7JRcL2i51Jb9VVeeY6QP"
        },
        {
            "direction": "Right",
            "hash": "CQoiwaCYqcJxZTT9bqceKTGUffZiKQNKPf6YUvXihEQJ"
        },
        {
            "direction": "Right",
            "hash": "DntvNk8Ugyu6ZdAUTV39MrPUrXQUFJKVaBUput6GMZiq"
        },
        {
            "direction": "Left",
            "hash": "4ZXzvj47NPZXfwV6N2Z2TCs52AX143bKGTUNQR4KuL5F"
        },
        {
            "direction": "Left",
            "hash": "6Czm39v4AvX1Xc5NZdsB94BNhawYhPAXRqyP3BephTyV"
        },
        {
            "direction": "Right",
            "hash": "tojBg1nCgpCEpD3ssM4rTibXuCNQ6Bdfq7iByhPvukD"
        },
        {
            "direction": "Right",
            "hash": "FHTGPaTNPPfcQ1yGuVCz1LgRxkQDjuSX4bk4L8kgDgQq"
        },
        {
            "direction": "Right",
            "hash": "837fc2U3xTc7fMPPPvaXd2GzTkJhVWRxznk4xnzqg7kz"
        },
        {
            "direction": "Left",
            "hash": "CAyu4UBn9JTTbq13pUGjY6nXCvjDaRzKwepwpJcpRLpn"
        },
        {
            "direction": "Left",
            "hash": "6ejd5xCdeRefBX34FoXBv4V2hVcRa2S89dnymWbCdfpj"
        },
        {
            "direction": "Right",
            "hash": "DYzHCZNv5VR8hR6dvYsA2CK8GaruXYA3GJmABpqB4rp"
        },
        {
            "direction": "Right",
            "hash": "D9BmTFSNCoU9ZzKLANz8J11UBhNpWAGnn6LH8YD5Sw1D"
        },
        {
            "direction": "Right",
            "hash": "CiUV5kcdjZpqw6iS2nYhiJZd5Prhh2ZHM7AXVoiCzr1R"
        },
        {
            "direction": "Right",
            "hash": "E71mnUNN1jWnyvrfKLsTAAaQ1rJtVwuRLiSjUqR8QKaT"
        },
        {
            "direction": "Left",
            "hash": "7x3QgcmcQu1Di5uYwP29nL4uRzLFv6tDpacZJrYTCDrY"
        },
        {
            "direction": "Left",
            "hash": "83Fsd3sdx5tsJkb6maBE1yViKiqbWCCNfJ4XZRsKnRZD"
        },
        {
            "direction": "Left",
            "hash": "AaT9jQmUvVpgDHdFkLR2XctaUVdTti49enmtbT5hsoyL"
        }]);

        let old = merkle::verify_hash(
            CryptoHash::from_str(root).unwrap(),
            &serde_json::from_value(old_proof).unwrap(),
            CryptoHash::from_str(old_block_hash).unwrap(),
        );
        assert!(old);
    }
}

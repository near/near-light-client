use crate::config::Config;
use borsh::BorshSerialize;
use near_primitives::{
    block_header::{ApprovalInner, BlockHeaderInnerLite},
    views::{
        validator_stake_view::ValidatorStakeView, BlockHeaderInnerLiteView,
        LightClientBlockLiteView, LightClientBlockView,
    },
};
// use flume::{Receiver, Sender};
use near_primitives_core::hash::CryptoHash;
use std::collections::HashMap;
// use views::LightClientBlockLiteView;

pub mod rpc;

pub type Header = LightClientBlockLiteView;

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

#[derive(Debug)]
pub enum SyncData {
    Sync { header: LightClientBlockView },
}

// TODO: futures::retry_after(next block time)
#[derive(Debug)]
pub struct LightClient {
    client: rpc::NearRpcClient,
    state: LightClientBlockLiteView,
    block_producers: HashMap<CryptoHash, Vec<ValidatorStakeView>>, // TODO can optimise this by short caching these by Pubkey and then storing pointers
    archival_headers: HashMap<CryptoHash, LightClientBlockLiteView>,
}

impl LightClient {
    // pub fn spawn(mut self, nrx: Receiver<Action>, htx: Sender<hbar::Action>) {
    //     tokio::spawn(async move {
    //         while let Ok(msg) = nrx.recv_async().await {
    //             match msg {
    //                 Action::GetHeader => {
    //                     log::info!("GetHeader message received");
    //                     let last_header = self.get_header().await?;
    //                     log::info!("sending header: {:?}", last_header);
    //                     htx.send(hbar::Action::Publish(super::Header::Near(last_header)));
    //                 }
    //                 Action::Shutdown => {
    //                     log::info!("Shutdown message received");
    //                     self.shutdown().await?;
    //                     break;
    //                 }
    //                 Action::GetProof => {
    //                     todo!("Noop getproof")
    //                 }
    //                 _ => {}
    //             }
    //         }
    //         Ok::<(), anyhow::Error>(())
    //     });
    // }

    pub async fn init(config: &Config) -> Self {
        log::debug!("Bootstrapping light client");

        let client = rpc::NearRpcClient::new(config.network.clone());

        let starting_head = client
            .fetch_latest_header(&config.starting_head)
            .await
            .expect("We need a starting header");

        log::info!("Got starting head: {:?}", starting_head.inner_lite.height);

        let mut block_producers = HashMap::new();
        block_producers.insert(
            starting_head.inner_lite.epoch_id,
            starting_head.next_bps.clone().unwrap(),
        );

        Self {
            client,
            state: LightClientBlockLiteView {
                prev_block_hash: starting_head.prev_block_hash,
                inner_rest_hash: starting_head.inner_rest_hash,
                inner_lite: starting_head.inner_lite,
            },
            block_producers,
            archival_headers: Default::default(),
        }
    }

    pub async fn sync(&mut self) -> anyhow::Result<bool> {
        // TODO: refactor
        let mut state: LightClientState = self.state.clone().into();

        let new_header = self
            .client
            .fetch_latest_header(&format!("{}", state.head.hash()))
            .await;

        if let Some(new_header) = new_header {
            let validated = self
                .block_producers
                .get(&state.head.inner_lite.epoch_id)
                .map(|bps| state.validate_and_update_head(&new_header, bps.clone()))
                .unwrap_or(false);

            if validated {
                if let Some((epoch, next_bps)) = state.next_bps {
                    self.block_producers.insert(epoch, next_bps);
                }

                self.archival_headers
                    .insert(self.state.inner_lite.epoch_id, self.state.clone());
                self.state = state.head.into();
            }
            Ok(true)
        } else {
            log::info!("No new header found");
            Ok(false)
        }
    }

    pub async fn header(&self) -> &Header {
        &self.state
    }

    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
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
                .to_vec(),
            block_view.prev_block_hash.as_bytes().to_vec()
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

    pub fn validate_and_update_head(
        &mut self,
        block_view: &LightClientBlockView,
        epoch_block_producers: Vec<ValidatorStakeView>,
    ) -> bool {
        let (_, _, approval_message) = self.reconstruct_light_client_block_view_fields(block_view);

        // (1) The block was already verified
        if block_view.inner_lite.height <= self.head.inner_lite.height {
            log::info!("Block has already been verified");
            return false;
        }

        // (2)
        if ![
            self.head.inner_lite.epoch_id,
            self.head.inner_lite.next_epoch_id,
        ]
        .contains(&block_view.inner_lite.epoch_id)
        {
            log::info!("Block is not in the current or next epoch");
            return false;
        }

        // (3) Same as next epoch and no new set, covering N + 2
        if block_view.inner_lite.epoch_id == self.head.inner_lite.next_epoch_id
            && block_view.next_bps.is_none()
        {
            log::info!("Block is in the next epoch but no new set");
            return false;
        }

        // (4) and (5)
        let mut total_stake = 0;
        let mut approved_stake = 0;

        for (maybe_signature, block_producer) in block_view
            .approvals_after_next
            .iter()
            .zip(epoch_block_producers.iter())
        {
            let vs = block_producer.clone().into_validator_stake();
            let bps_stake = vs.stake();
            let bps_pk = vs.public_key();

            total_stake += bps_stake;

            if let Some(signature) = maybe_signature {
                log::debug!(
                    "Checking if signature {} and message {:?} was signed by {}",
                    signature,
                    approval_message,
                    bps_pk
                );
                approved_stake += bps_stake;
                if !signature.verify(&approval_message, &bps_pk) {
                    log::warn!("Signature is invalid");
                    return false;
                }
            }
        }
        log::debug!("All signatures are valid");

        let threshold = total_stake * 2 / 3;
        if approved_stake <= threshold {
            log::warn!("Not enough stake approved");
            return false;
        }

        // (6)
        if let Some(next_bps) = &block_view.next_bps {
            let next_bps_hash = CryptoHash::hash_borsh(&next_bps);
            if next_bps_hash != block_view.inner_lite.next_bp_hash {
                log::warn!("Next block producers hash is invalid");
                return false;
            }

            self.next_bps = Some((
                self.head.inner_lite.next_epoch_id,
                next_bps.into_iter().map(|s| s.clone().into()).collect(),
            ));
        }

        let prev_head = self.head.inner_lite.height;
        self.head = LightClientBlockLiteView {
            prev_block_hash: block_view.prev_block_hash,
            inner_rest_hash: block_view.inner_rest_hash,
            inner_lite: block_view.inner_lite.clone(),
        };
        let new_head = self.head.inner_lite.height;
        log::info!("prev/current head: {}/{}", prev_head, new_head);

        true
    }
}

#[cfg(test)]
mod tests {
    use super::{
        rpc::{JsonRpcResult, NearRpcResult},
        *,
    };
    use core::str::FromStr;
    use serde_json;

    fn get_file(file: &str) -> JsonRpcResult {
        serde_json::from_reader(std::fs::File::open(file).unwrap()).unwrap()
    }

    fn get_previous_header() -> LightClientBlockView {
        if let NearRpcResult::NextBlock(header) = get_file("fixtures/2_previous_epoch.json").result
        {
            header
        } else {
            panic!("Expected block header")
        }
    }

    fn get_next_header() -> LightClientBlockView {
        if let NearRpcResult::NextBlock(header) = get_file("fixtures/1_current_epoch.json").result {
            header
        } else {
            panic!("Expected block header")
        }
    }

    fn get_previous() -> LightClientBlockView {
        let s: JsonRpcResult =
            serde_json::from_reader(std::fs::File::open("fixtures/2_previous_epoch.json").unwrap())
                .unwrap();
        if let NearRpcResult::NextBlock(header) = s.result {
            header
        } else {
            panic!("Expected block header")
        }
    }
    fn get_previous_previous() -> LightClientBlockView {
        let s: JsonRpcResult =
            serde_json::from_reader(std::fs::File::open("fixtures/3_previous_epoch.json").unwrap())
                .unwrap();
        if let NearRpcResult::NextBlock(header) = s.result {
            header
        } else {
            panic!("Expected block header")
        }
    }

    fn get_next_bps() -> Vec<ValidatorStakeView> {
        get_previous().next_bps.unwrap()
    }

    fn get_current() -> LightClientBlockView {
        let s: JsonRpcResult =
            serde_json::from_reader(std::fs::File::open("fixtures/1_current_epoch.json").unwrap())
                .unwrap();
        if let NearRpcResult::NextBlock(header) = s.result {
            header
        } else {
            panic!("Expected block header")
        }
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

    #[test]
    fn test_validate() {
        pretty_env_logger::init();
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

        assert!(state.validate_and_update_head(
            &headers_by_epoch[1].1.clone(),
            headers_by_epoch[0].1.next_bps.clone().unwrap(),
        ));
    }

    // #[test]
    // fn test_can_verify_one_sig() {
    // 	let prev_hash =
    // 		CryptoHash::from_str("7aLAqDbJtwYQTVJz8xHTcRUgTYDGcYGkBptPCNXBrpSA").unwrap();

    // 	let file = "fixtures/well_known_header.json";
    // 	let head: BlockHeaderInnerLite =
    // 		serde_json::from_reader(std::fs::File::open(file).unwrap()).unwrap();

    // 	let view: LightClientBlockLiteView = LightClientBlockView {
    // 		inner_lite: BlockHeaderInnerLiteView::from(head.clone()),
    // 		inner_rest_hash,
    // 		prev_block_hash: prev_hash,
    // 		// Not needed for this test
    // 		approvals_after_next: vec![],
    // 		next_bps: None,
    // 		next_block_inner_hash: CryptoHash::default(),
    // 	}
    // 	.into();

    // 	let mut state = LightClientState { head: view, next_bps: None };
    // 	let (current_block_hash, next_block_hash, approval_message) =
    // 		state.reconstruct_light_client_block_view_fields(&get_next().clone().into());

    // 	let signature = ed25519_dalek::Signature::from_bytes(&[0; 64]).unwrap();
    // 	if let Signature::ED25519(signature) = signature {
    // 		let first_validator = &get_previous_previous().next_bps.unwrap()[0];
    // 		log::info!("first_validator: {:?}", first_validator);

    // 		// FIXME: need to get these, currently verifying against the next bps is why this test
    // 		// fails
    // 		let signer = first_validator.public_key.unwrap_as_ed25519();
    // 		let signer = ed25519_dalek::PublicKey::from_bytes(&signer.0).unwrap();

    // 		signer.verify(&approval_message[..], &signature).unwrap();
    // 	} else {
    // 		panic!("Expected ed25519 signature")
    // 	}
    // }

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
}

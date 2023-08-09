use super::{block_header::BlockHeaderInnerLite, merkle::combine_hash};
use borsh::{BorshDeserialize, BorshSerialize};
use near_crypto::{Signature, PublicKey};
use near_primitives_core::hash::hash;
use near_primitives_core::hash::CryptoHash;
use near_primitives_core::serialize::dec_format;
use near_primitives_core::types::{AccountId, Balance, BlockHeight};

#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LightClientBlockView {
    pub prev_block_hash: CryptoHash,
    pub next_block_inner_hash: CryptoHash,
    pub inner_lite: BlockHeaderInnerLiteView,
    pub inner_rest_hash: CryptoHash,
    pub next_bps: Option<Vec<ValidatorStakeView>>,
    pub approvals_after_next: Vec<Option<Signature>>,
}

#[derive(
    PartialEq,
    Eq,
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct BlockHeaderInnerLiteView {
    pub height: BlockHeight,
    pub epoch_id: CryptoHash,
    pub next_epoch_id: CryptoHash,
    pub prev_state_root: CryptoHash,
    pub outcome_root: CryptoHash,
    /// Legacy json number. Should not be used.
    pub timestamp: u64,
    #[serde(with = "dec_format")]
    pub timestamp_nanosec: u64,
    pub next_bp_hash: CryptoHash,
    pub block_merkle_root: CryptoHash,
}

impl From<BlockHeaderInnerLite> for BlockHeaderInnerLiteView {
    fn from(block_header: BlockHeaderInnerLite) -> Self {
        Self {
            height: block_header.height,
            epoch_id: block_header.epoch_id.0,
            next_epoch_id: block_header.next_epoch_id.0,
            prev_state_root: block_header.prev_state_root,
            outcome_root: block_header.outcome_root,
            timestamp: block_header.timestamp,
            timestamp_nanosec: block_header.timestamp,
            next_bp_hash: block_header.next_bp_hash,
            block_merkle_root: block_header.block_merkle_root,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LightClientBlockLiteView {
    pub prev_block_hash: CryptoHash,
    pub inner_rest_hash: CryptoHash,
    pub inner_lite: BlockHeaderInnerLiteView,
}

impl From<LightClientBlockView> for LightClientBlockLiteView {
    fn from(block: LightClientBlockView) -> Self {
        Self {
            prev_block_hash: block.prev_block_hash,
            inner_rest_hash: block.inner_rest_hash,
            inner_lite: block.inner_lite,
        }
    }
}

impl LightClientBlockLiteView {
    pub fn hash(&self) -> CryptoHash {
        let block_header_inner_lite: BlockHeaderInnerLite = self.inner_lite.clone().into();
        combine_hash(
            &combine_hash(
                &hash(&borsh::to_vec(&block_header_inner_lite).unwrap()),
                &self.inner_rest_hash,
            ),
            &self.prev_block_hash,
        )
    }
}

/// Stores validator and its stake.
#[derive(BorshSerialize, serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "validator_stake_struct_version")]
pub enum ValidatorStakeView {
    V1(ValidatorStakeV1),
}

impl ValidatorStakeView {
    pub fn account_id(&self) -> &AccountId {
        match self {
            ValidatorStakeView::V1(v) => &v.account_id,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        match self {
            ValidatorStakeView::V1(v) => &v.public_key,
        }
    }

    pub fn stake(&self) -> Balance {
        match self {
            ValidatorStakeView::V1(v) => v.stake,
        }
    }

    pub fn unwrap_v1(self) -> ValidatorStakeV1 {
        match self {
            ValidatorStakeView::V1(v) => v,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, BorshSerialize)]
pub struct ValidatorStakeV1 {
    pub account_id: AccountId,
    pub public_key: PublicKey,
    #[serde(with = "dec_format")]
    pub stake: Balance,
}

use crate::prelude::*;
use error::Error;
pub use merkle_util::*;
pub use near_crypto::{PublicKey, Signature};
pub use near_primitives::{
    block_header::ApprovalInner,
    block_header::BlockHeaderInnerLite,
    merkle::MerklePathItem,
    types::{validator_stake::ValidatorStake, BlockHeight, EpochId},
    views::{
        validator_stake_view::ValidatorStakeView, BlockHeaderInnerLiteView, LightClientBlockView,
    },
};

pub mod config;
pub mod error;
pub mod merkle_util;
pub mod prelude;
// Lightweight batch protocol with lookups for proofs
pub mod experimental;

#[derive(Debug)]
pub struct Synced {
    pub new_head: Header,
    pub next_bps: Option<(EpochId, Vec<ValidatorStake>)>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Proof {
    Basic {
        head_block_root: CryptoHash,
        proof: Box<BasicProof>,
    },
    Experimental(experimental::Proof),
}

impl From<(CryptoHash, BasicProof)> for Proof {
    fn from((head_block_root, proof): (CryptoHash, BasicProof)) -> Self {
        Self::Basic {
            head_block_root,
            proof: Box::new(proof),
        }
    }
}

impl From<experimental::Proof> for Proof {
    fn from(proof: experimental::Proof) -> Self {
        Self::Experimental(proof)
    }
}

impl Proof {
    pub fn block_merkle_root(&self) -> &CryptoHash {
        match self {
            Self::Basic {
                head_block_root, ..
            } => head_block_root,
            Self::Experimental(proof) => &proof.head_block_root,
        }
    }
}

pub struct Protocol;

impl Protocol {
    pub fn sync(
        head: &Header,
        epoch_bps: &[ValidatorStake],
        next_block: LightClientBlockView,
    ) -> Result<Synced> {
        Self::ensure_not_already_verified(head, &next_block.inner_lite.height)?;
        Self::ensure_epoch_is_current_or_next(head, &next_block.inner_lite.epoch_id)?;
        Self::ensure_if_next_epoch_contains_next_bps(
            head,
            &next_block.inner_lite.epoch_id,
            &next_block.next_bps,
        )?;

        let new_head = Header {
            prev_block_hash: next_block.prev_block_hash,
            inner_rest_hash: next_block.inner_rest_hash,
            inner_lite: next_block.inner_lite.clone(),
        };

        let approval_message = Self::reconstruct_approval_message(&next_block).unwrap();

        let StakeInfo { total, approved } = Self::validate_signatures(
            &next_block.approvals_after_next,
            epoch_bps,
            &approval_message,
        );

        Self::ensure_stake_is_sufficient(&total, &approved)?;

        log::trace!(
            "prev/current head: {}/{}",
            head.inner_lite.height,
            new_head.inner_lite.height
        );

        Ok(Synced {
            new_head,
            next_bps: Self::ensure_next_bps_is_valid(
                &next_block.inner_lite.next_bp_hash,
                next_block.next_bps,
            )?
            .map(|next_bps| next_bps.into_iter().map(Into::into).collect())
            .map(|next_bps| (EpochId(head.inner_lite.next_epoch_id), next_bps)),
        })
        .map(|synced| {
            log::debug!("Synced new head: {:?}", synced.new_head);
            synced
        })
    }
    pub fn inclusion_proof_verify(proof: Proof) -> Result<bool> {
        match proof {
            Proof::Experimental(proof) => Ok(experimental::verify_proof(proof)),
            Proof::Basic {
                head_block_root,
                proof,
            } => {
                let block_hash = proof.block_header_lite.hash();
                let block_hash_matches = block_hash == proof.outcome_proof.block_hash;

                let outcome_hash = CryptoHash::hash_borsh(proof.outcome_proof.to_hashes());

                let outcome_verified = Self::verify_outcome(
                    &outcome_hash,
                    proof.outcome_proof.proof.iter(),
                    proof.outcome_root_proof.iter(),
                    &proof.block_header_lite.inner_lite.outcome_root,
                );

                let block_verified =
                    Self::verify_block(&head_block_root, proof.block_proof.iter(), &block_hash);

                log::debug!(
                    "shard outcome included: {:?}, block included: {:?}",
                    outcome_verified,
                    block_verified
                );
                Ok(block_hash_matches && outcome_verified && block_verified).map(|verified| {
                    log::debug!("Verified proof {:?}", verified);
                    verified
                })
            }
        }
    }

    pub(crate) fn verify_outcome<'a>(
        outcome_hash: &CryptoHash,
        outcome_proof: impl Iterator<Item = &'a MerklePathItem>,
        outcome_root_proof: impl Iterator<Item = &'a MerklePathItem>,
        expected_outcome_root: &CryptoHash,
    ) -> bool {
        let outcome_root = compute_root_from_path(outcome_proof, *outcome_hash);
        #[cfg(test)]
        println!("outcome_root: {:?}", hex::encode(&outcome_root));

        let leaf = CryptoHash::hash_borsh(outcome_root);
        #[cfg(test)]
        println!("leaf: {:?}", hex::encode(&leaf));

        let outcome_root = compute_root_from_path(outcome_root_proof, leaf);
        #[cfg(test)]
        println!("outcome_root: {:?}", hex::encode(&outcome_root));
        log::debug!("outcome_root: {:?}", outcome_root);

        &outcome_root == expected_outcome_root
    }

    pub(crate) fn verify_block<'a>(
        block_merkle_root: &CryptoHash,
        block_proof: impl Iterator<Item = &'a MerklePathItem>,
        block_hash: &CryptoHash,
    ) -> bool {
        verify_hash(*block_merkle_root, block_proof, *block_hash)
    }

    pub fn reconstruct_approval_message(block_view: &LightClientBlockView) -> Option<Vec<u8>> {
        let new_head = Header {
            prev_block_hash: block_view.prev_block_hash,
            inner_rest_hash: block_view.inner_rest_hash,
            inner_lite: block_view.inner_lite.clone(),
        };

        let next_block_hash = combine_hash(&block_view.next_block_inner_hash, &new_head.hash());

        let endorsement = ApprovalInner::Endorsement(next_block_hash);

        let approval_message = {
            let mut temp_vec = Vec::new();
            BorshSerialize::serialize(&endorsement, &mut temp_vec).ok()?;
            //temp_vec.extend_from_slice(&(endorsement.try_to_vec().ok()?[..]));
            temp_vec.extend_from_slice(&((block_view.inner_lite.height + 2).to_le_bytes()[..]));
            println!("temp_vec len: {:?}", temp_vec.len());
            temp_vec
        };

        log::debug!("Next block hash: {}", next_block_hash);
        log::debug!("Approval message: {:?}", approval_message);
        Option::Some(approval_message)
    }

    pub fn ensure_not_already_verified(
        head: &Header,
        block_height: &BlockHeight,
    ) -> Result<(), Error> {
        if block_height <= &head.inner_lite.height {
            Err(Error::BlockAlreadyVerified)
        } else {
            Ok(())
        }
    }

    pub fn ensure_epoch_is_current_or_next(
        head: &Header,
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
        head: &Header,
        epoch_id: &CryptoHash,
        next_bps: &Option<Vec<ValidatorStakeView>>,
    ) -> Result<(), Error> {
        if &head.inner_lite.next_epoch_id == epoch_id && next_bps.is_none() {
            log::debug!("Block is in the next epoch but no new set");
            Err(Error::NextBpsInvalid)
        } else {
            Ok(())
        }
    }

    pub fn validate_signatures(
        signatures: &[Option<Box<Signature>>],
        epoch_bps: &[ValidatorStake],
        approval_message: &[u8],
    ) -> StakeInfo {
        signatures
            .iter()
            .zip(epoch_bps.iter())
            .fold((0, 0), |(total_stake, approved_stake), (sig, vs)| {
                let pk = vs.public_key();
                let stake = vs.stake();
                let total_stake = total_stake + stake;

                let approved_stake = match Self::validate_signature(approval_message, sig, pk) {
                    Ok(_) => approved_stake + stake,
                    Err(Error::SignatureInvalid) | Err(Error::ValidatorNotSigned) => approved_stake,
                    Err(_) => approved_stake,
                };

                (total_stake, approved_stake)
            })
            .into()
    }

    pub fn validate_signature(
        msg: &[u8],
        sig: &Option<Box<Signature>>,
        pk: &PublicKey,
    ) -> Result<(), Error> {
        match sig {
            Some(signature) if signature.verify(msg, pk) => {
                log::trace!("{} {:?} pk {} approved", signature, msg, pk);
                Ok(())
            }
            Some(signature) => {
                log::debug!("{} invalid sig {}", pk, signature);
                Err(Error::SignatureInvalid)
            }
            _ => {
                log::trace!("{} signature not approved", pk);
                Err(Error::ValidatorNotSigned)
            }
        }
    }

    pub fn ensure_stake_is_sufficient(
        total_stake: &u128,
        approved_stake: &u128,
    ) -> Result<(), Error> {
        let threshold = total_stake / 3 * 2;

        if approved_stake <= &threshold {
            log::debug!("Not enough stake approved");
            Err(Error::NotEnoughApprovedStake)
        } else {
            Ok(())
        }
    }

    pub fn ensure_next_bps_is_valid(
        expected_hash: &CryptoHash,
        next_bps: Option<Vec<ValidatorStakeView>>,
    ) -> Result<Option<Vec<ValidatorStakeView>>, Error> {
        if let Some(next_bps) = next_bps {
            let next_bps_hash = CryptoHash::hash_borsh(next_bps.clone());

            if &next_bps_hash == expected_hash {
                Ok(Some(next_bps))
            } else {
                log::warn!("Next block producers hash is invalid");
                Err(Error::NextBpsInvalid)
            }
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeInfo {
    pub total: u128,
    pub approved: u128,
}

impl From<(u128, u128)> for StakeInfo {
    fn from((total, approved): (u128, u128)) -> Self {
        Self { total, approved }
    }
}

#[macro_export]
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

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use near_jsonrpc_primitives::types::light_client::RpcLightClientExecutionProofResponse;
    use serde_json::{self};

    fn fixture(file: &str) -> LightClientBlockView {
        serde_json::from_reader(std::fs::File::open(format!("../../fixtures/{}", file)).unwrap())
            .unwrap()
    }

    fn get_next_epoch() -> LightClientBlockView {
        fixture("2.json")
    }

    fn get_first_epoch() -> LightClientBlockView {
        fixture("1.json")
    }

    fn get_current_epoch() -> LightClientBlockView {
        fixture("current_epoch.json")
    }

    fn view_to_lite_view(h: LightClientBlockView) -> Header {
        Header {
            prev_block_hash: h.prev_block_hash,
            inner_rest_hash: h.inner_rest_hash,
            inner_lite: h.inner_lite,
        }
    }

    fn test_state() -> (Header, Vec<ValidatorStake>, LightClientBlockView) {
        let first = get_first_epoch();
        let next = get_next_epoch();

        (
            view_to_lite_view(first.clone()),
            first
                .next_bps
                .clone()
                .unwrap()
                .into_iter()
                .map(Into::into)
                .collect(),
            next,
        )
    }

    #[test]
    fn test_sync_across_epoch_boundaries() {
        let (mut head, mut next_bps, next_block) = test_state();
        let mut next_epoch_id = EpochId(head.inner_lite.next_epoch_id);

        let mut sync_and_update = |next_block: LightClientBlockView| {
            let sync_next = Protocol::sync(&head, &next_bps, next_block.clone()).unwrap();
            // Assert we matched the epoch id for the new BPS
            assert_eq!(
                head.inner_lite.next_epoch_id,
                sync_next.next_bps.as_ref().unwrap().0 .0
            );

            head = sync_next.new_head;
            next_bps = sync_next.next_bps.unwrap().1;

            // Assert new head is the new block
            assert_eq!(head.inner_lite, next_block.inner_lite);
            // Assert new BPS is from the next block producers because we're
            // in an epoch boundary
            assert_eq!(
                &next_bps,
                &next_block
                    .next_bps
                    .unwrap()
                    .into_iter()
                    .map(Into::into)
                    .collect_vec()
            );
            next_epoch_id.0 = head.inner_lite.next_epoch_id;
        };

        // Do first sync
        sync_and_update(next_block.clone());

        // Get next header, do next sync
        let next_block = get_current_epoch();
        sync_and_update(next_block.clone());
    }

    #[test]
    fn test_validate_already_verified() {
        pretty_env_logger::try_init().ok();

        let (head, _, _) = test_state();
        assert_eq!(
            Protocol::ensure_not_already_verified(&head, &BlockHeight::MIN),
            Err(Error::BlockAlreadyVerified)
        );
    }

    #[test]
    fn test_validate_bad_epoch() {
        pretty_env_logger::try_init().ok();

        let (head, _, _) = test_state();
        assert_eq!(
            Protocol::ensure_epoch_is_current_or_next(
                &head,
                &CryptoHash::hash_bytes(b"bogus hash")
            ),
            Err(Error::BlockNotCurrentOrNextEpoch)
        );
    }

    #[test]
    fn test_next_epoch_bps_invalid() {
        pretty_env_logger::try_init().ok();

        let (head, _, mut next_block) = test_state();
        next_block.next_bps = None;

        assert_eq!(
            Protocol::ensure_if_next_epoch_contains_next_bps(
                &head,
                &next_block.inner_lite.epoch_id,
                &next_block.next_bps
            ),
            Err(Error::NextBpsInvalid)
        );
    }

    #[test]
    fn test_next_invalid_signature() {
        pretty_env_logger::try_init().ok();

        let (_, next_bps, next_block) = test_state();
        assert_eq!(
            Protocol::validate_signature(
                &b"bogus approval message"[..],
                &next_block.approvals_after_next[0],
                next_bps[0].public_key(),
            ),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn test_next_invalid_signatures_no_approved_stake() {
        pretty_env_logger::try_init().ok();

        let (_, next_bps, mut next_block) = test_state();

        let approval_message = Protocol::reconstruct_approval_message(&next_block);
        // Nobody signed anything
        next_block.approvals_after_next = next_block
            .approvals_after_next
            .iter()
            .cloned()
            .map(|_| None)
            .collect();

        let StakeInfo { total, approved } = Protocol::validate_signatures(
            &next_block.approvals_after_next,
            &next_bps.clone(),
            &approval_message.unwrap(),
        );

        assert_eq!((total, approved), (512915271547861520119028536348929, 0));
    }

    #[test]
    fn test_next_invalid_signatures_stake_isnt_sufficient() {
        pretty_env_logger::try_init().ok();

        let (_, next_bps, next_block) = test_state();

        let approval_message = Protocol::reconstruct_approval_message(&next_block);

        let StakeInfo { total, approved } = Protocol::validate_signatures(
            &next_block.approvals_after_next,
            &next_bps,
            &approval_message.unwrap(),
        );

        assert_eq!(
            (total, approved),
            (
                512915271547861520119028536348929,
                345140782903867823005444871054881
            )
        );

        assert!(Protocol::ensure_stake_is_sufficient(&total, &approved).is_ok());

        let min_approval_amount = (total / 3) * 2;

        assert_eq!(
            Protocol::ensure_stake_is_sufficient(&total, &(min_approval_amount - 1)),
            Err(Error::NotEnoughApprovedStake)
        );
    }

    #[test]
    fn test_next_bps_invalid_hash() {
        pretty_env_logger::try_init().ok();

        let (_, _, next_block) = test_state();

        assert_eq!(
            Protocol::ensure_next_bps_is_valid(
                &CryptoHash::hash_borsh(b"invalid"),
                next_block.next_bps
            ),
            Err(Error::NextBpsInvalid)
        );
    }

    #[test]
    fn test_next_bps() {
        pretty_env_logger::try_init().ok();

        let (_, _, next_block) = test_state();

        assert_eq!(
            Protocol::ensure_next_bps_is_valid(
                &next_block.inner_lite.next_bp_hash,
                next_block.next_bps.clone()
            )
            .unwrap(),
            next_block.next_bps
        );
    }

    #[test]
    fn test_next_bps_noop_on_empty() {
        pretty_env_logger::try_init().ok();

        let (_, _, next_block) = test_state();
        assert_eq!(
            Protocol::ensure_next_bps_is_valid(&next_block.inner_lite.next_bp_hash, None).unwrap(),
            None
        );
    }

    #[test]
    fn test_outcome_root() {
        pretty_env_logger::try_init().ok();
        let req = r#"{"outcome_proof":{"proof":[],"block_hash":"5CY72FinjVV2Hd5zRikYYMaKh67pftXJsw8vwRXAUAQF","id":"9UhBumQ3eEmPH5ALc3NwiDCQfDrFakteRD7rHE9CfZ32","outcome":{"logs":[],"receipt_ids":["2mrt6jXKwWzkGrhucAtSc8R3mjrhkwCjnqVckPdCMEDo"],"gas_burnt":2434069818500,"tokens_burnt":"243406981850000000000","executor_id":"datayalla.testnet","status":{"SuccessReceiptId":"2mrt6jXKwWzkGrhucAtSc8R3mjrhkwCjnqVckPdCMEDo"},"metadata":{"version":1,"gas_profile":null}}},"outcome_root_proof":[{"hash":"9f7YjLvzvSspJMMJ3DDTrFaEyPQ5qFqQDNoWzAbSTjTy","direction":"Right"},{"hash":"67ZxFmzWXbWJSyi7Wp9FTSbbJx2nMr7wSuW3EP1cJm4K","direction":"Left"}],"block_header_lite":{"prev_block_hash":"AEnTyGRrk2roQkYSWoqYhzkbp5SWWJtCd71ZYyj1P26i","inner_rest_hash":"G25j8jSWRyrXV317cPC3qYA4SyJWXsBfErjhBYQkxw5A","inner_lite":{"height":134481525,"epoch_id":"4tBzDozzGED3QiCRURfViVuyJy5ikaN9dVH7m2MYkTyw","next_epoch_id":"9gYJSiT3TQbKbwui5bdbzBA9PCMSSfiffWhBdMtcasm2","prev_state_root":"EwkRecSP8GRvaxL7ynCEoHhsL1ksU6FsHVLCevcccF5q","outcome_root":"8Eu5qpDUMpW5nbmTrTKmDH2VYqFEHTKPETSTpPoyGoGc","timestamp":1691615068679535000,"timestamp_nanosec":"1691615068679535094","next_bp_hash":"8LCFsP6LeueT4X3PEni9CMvH7maDYpBtfApWZdXmagss","block_merkle_root":"583vb6csYnczHyt5z6Msm4LzzGkceTZHdvXjC8vcWeGK"}},"block_proof":[{"hash":"AEnTyGRrk2roQkYSWoqYhzkbp5SWWJtCd71ZYyj1P26i","direction":"Left"},{"hash":"HgZaHXpb5zs4rxUQTeW69XBNLBJoo4sz2YEDh7aFnMpC","direction":"Left"},{"hash":"EYNXYsnESQkXo7B27a9xu6YgbDSyynNcByW5Q2SqAaKH","direction":"Right"},{"hash":"AbKbsD7snoSnmzAtwNqXLBT5sm7bZr48GCCLSdksFuzi","direction":"Left"},{"hash":"7KKmS7n3MtCfv7UqciidJ24Abqsk8m85jVQTh94KTjYS","direction":"Left"},{"hash":"5nKA1HCZMJbdCccZ16abZGEng4sMoZhKez74rcCFjnhL","direction":"Left"},{"hash":"BupagAycSLD7v42ksgMKJFiuCzCdZ6ksrGLwukw7Vfe3","direction":"Right"},{"hash":"D6v37P4kcVJh8N9bV417eqJoyMeQbuZ743oNsbKxsU7z","direction":"Right"},{"hash":"8sWxxbe1rdquP5VdYfQbw1UvtcXDRansJYJV5ySzyow4","direction":"Right"},{"hash":"CmKVKWRqEqi4UaeKKYXpPSesYqdQYwHQM3E4xLKEUAj8","direction":"Left"},{"hash":"3TvjFzVyPBvPpph5zL6VCASLCxdNeiKV6foPwUpAGqRv","direction":"Left"},{"hash":"AnzSG9f91ePS6L6ii3eAkocp4iKjp6wjzSwWsDYWLnMX","direction":"Right"},{"hash":"FYVJDL4T6c87An3pdeBvntB68NzpcPtpvLP6ifjxxNkr","direction":"Left"},{"hash":"2YMF6KE8XTz7Axj3uyAoFbZisWej9Xo8mxgVtauWCZaV","direction":"Left"},{"hash":"4BHtLcxqNfWSneBdW76qsd8om8Gjg58Qw5BX8PHz93hf","direction":"Left"},{"hash":"7G3QUT7NQSHyXNQyzm8dsaYrFk5LGhYaG7aVafKAekyG","direction":"Left"},{"hash":"3XaMNnvnX69gGqBJX43Na1bSTJ4VUe7z6h5ZYJsaSZZR","direction":"Left"},{"hash":"FKu7GtfviPioyAGXGZLBVTJeG7KY5BxGwuL447oAZxiL","direction":"Right"},{"hash":"BePd7DPKUQnGtnSds5fMJGBUwHGxSNBpaNLwceJGUcJX","direction":"Left"},{"hash":"2BVKWMd9pXZTEyE9D3KL52hAWAyMrXj1NqutamyurrY1","direction":"Left"},{"hash":"EWavHKhwQiT8ApnXvybvc9bFY6aJYJWqBhcrZpubKXtA","direction":"Left"},{"hash":"83Fsd3sdx5tsJkb6maBE1yViKiqbWCCNfJ4XZRsKnRZD","direction":"Left"},{"hash":"AaT9jQmUvVpgDHdFkLR2XctaUVdTti49enmtbT5hsoyL","direction":"Left"}]}"#;
        let p: RpcLightClientExecutionProofResponse = serde_json::from_str(req).unwrap();

        let outcome_hash = CryptoHash::hash_borsh(p.outcome_proof.to_hashes());

        let root_matches = Protocol::verify_outcome(
            &outcome_hash,
            p.outcome_proof.proof.iter(),
            p.outcome_root_proof.iter(),
            &p.block_header_lite.inner_lite.outcome_root,
        );
        assert!(root_matches);
    }

    #[test]
    fn statically_test_lens() {
        println!("approval: {:?}", std::mem::size_of::<ApprovalInner>());
    }
}

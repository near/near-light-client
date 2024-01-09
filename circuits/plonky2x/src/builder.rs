use crate::variables::{
    Block, BlockHeight, BuildEndorsement, CryptoHash, EpochBlockProducers, Header, HeaderInner,
    InnerLiteHash, MerklePath, Proof, PublicKey, Signature, StakeInfo, ValidatorStake,
    MAX_EPOCH_VALIDATORS,
};
use plonky2x::frontend::merkle::tendermint::TendermintMerkleTree;
use plonky2x::prelude::*;

pub trait Verify<L: PlonkParameters<D>, const D: usize> {
    fn ensure_not_already_verified(
        &mut self,
        head: &Header,
        block_height: &BlockHeight,
    ) -> BoolVariable;

    fn ensure_epoch_is_current_or_next(
        &mut self,
        head: &Header,
        epoch_id: &CryptoHash,
    ) -> BoolVariable;

    fn ensure_if_next_epoch_contains_next_bps(
        &mut self,
        head: &Header,
        epoch_id: &CryptoHash,
        next_bps: &EpochBlockProducers,
    ) -> BoolVariable;

    fn validate_signatures(
        &mut self,
        is_active: ArrayVariable<BoolVariable, MAX_EPOCH_VALIDATORS>,
        signatures: ArrayVariable<Signature, MAX_EPOCH_VALIDATORS>,
        epoch_bps: ArrayVariable<ValidatorStake, MAX_EPOCH_VALIDATORS>,
        approval_message_hash: Bytes32Variable,
    ) -> StakeInfo;

    fn ensure_stake_is_sufficient(&mut self, stake: &StakeInfo) -> BoolVariable;

    fn ensure_next_bps_is_valid(
        &mut self,
        expected_hash: &CryptoHash,
        next_bps_hash: Option<&CryptoHash>,
    ) -> BoolVariable;

    fn ensure_block_hash_matches_outcome(
        &mut self,
        head: &Header,
        outcome_proof_block_hash: &CryptoHash,
    ) -> BoolVariable;

    fn ensure_block_hash_matches_outcome_hashed(
        &mut self,
        head: &CryptoHash,
        outcome_proof_block_hash: &CryptoHash,
    ) -> BoolVariable;

    fn verify_outcome<const OD: usize, const ORD: usize>(
        &mut self,
        expected: &CryptoHash,
        outcome_proof: &MerklePath<OD>,
        outcome_hash: &CryptoHash,
        outcome_root_proof: &MerklePath<ORD>,
    ) -> BoolVariable;

    fn verify_block<const BD: usize>(
        &mut self,
        expected: &CryptoHash,
        block_proof: &MerklePath<BD>,
        block_hash: &CryptoHash,
    ) -> BoolVariable;

    fn header_hash(
        &mut self,
        inner_lite_hash: &HeaderInner,
        inner_rest_hash: &CryptoHash,
        prev_block_hash: &CryptoHash,
    ) -> CryptoHash;

    fn inner_lite_hash(&mut self, inner_lite: &HeaderInner) -> CryptoHash;

    fn assertx(&mut self, condition: BoolVariable);
}

impl<L: PlonkParameters<D>, const D: usize> Verify<L, D> for CircuitBuilder<L, D> {
    fn ensure_not_already_verified(
        &mut self,
        head: &Header,
        block_height: &BlockHeight,
    ) -> BoolVariable {
        self.gt(*block_height, head.inner_lite.height)
    }

    fn ensure_epoch_is_current_or_next(
        &mut self,
        head: &Header,
        epoch_id: &CryptoHash,
    ) -> BoolVariable {
        let epoch = self.is_equal(head.inner_lite.epoch_id, *epoch_id);
        let next_epoch = self.is_equal(head.inner_lite.next_epoch_id, *epoch_id);

        self.or(epoch, next_epoch)
    }

    fn ensure_if_next_epoch_contains_next_bps(
        &mut self,
        head: &Header,
        epoch_id: &CryptoHash,
        next_bps: &EpochBlockProducers,
    ) -> BoolVariable {
        let is_next_epoch = self.is_equal(head.inner_lite.next_epoch_id, *epoch_id);
        let is_not_empty = self.constant(next_bps.bps.len() > 0);
        let ok_anyway = self.constant(true);
        self.select(is_next_epoch, is_not_empty, ok_anyway)
    }

    // TODO: does not build active participants
    fn validate_signatures(
        &mut self,
        is_active: ArrayVariable<BoolVariable, MAX_EPOCH_VALIDATORS>,
        signatures: ArrayVariable<Signature, MAX_EPOCH_VALIDATORS>,
        epoch_bps: ArrayVariable<ValidatorStake, MAX_EPOCH_VALIDATORS>,
        approval_message_hash: Bytes32Variable,
    ) -> StakeInfo {
        let messages = [approval_message_hash.0; MAX_EPOCH_VALIDATORS];
        let pubkeys: Vec<PublicKey> = epoch_bps
            .data
            .iter()
            .map(|vs| vs.public_key.clone())
            .collect();

        const MSG_LEN: usize = 32;

        // Here we ensure that all active participants have signed
        self.curta_eddsa_verify_sigs_conditional::<MSG_LEN, MAX_EPOCH_VALIDATORS>(
            is_active.clone(),
            None,
            ArrayVariable::new(messages.to_vec()),
            signatures,
            ArrayVariable::new(pubkeys),
        );

        let mut total_stake = self.constant(0);
        let mut approved_stake = self.constant(0);

        // Collect all approvals
        for (i, bps) in epoch_bps.data.iter().enumerate() {
            if is_active.data.get(i).is_some() {
                approved_stake = self.add(approved_stake, bps.stake);
            }
            total_stake = self.add(total_stake, bps.stake);
        }

        StakeInfo {
            total_stake,
            approved_stake,
        }
    }

    fn ensure_stake_is_sufficient(&mut self, stake: &StakeInfo) -> BoolVariable {
        let denominator = self.constant(3);
        let numerator = self.constant(2);

        let approved = self.mul(stake.approved_stake, numerator);
        let threshold = self.mul(stake.total_stake, denominator);

        self.gte(approved, threshold)
    }

    fn ensure_next_bps_is_valid(
        &mut self,
        expected_hash: &CryptoHash,
        next_bps_hash: Option<&CryptoHash>,
    ) -> BoolVariable {
        if let Some(next_bps) = next_bps_hash {
            self.is_equal(*next_bps, *expected_hash)
        } else {
            self._true()
        }
    }

    fn ensure_block_hash_matches_outcome(
        &mut self,
        head: &Header,
        outcome_proof_block_hash: &CryptoHash,
    ) -> BoolVariable {
        let hash = self.header_hash(
            &head.inner_lite,
            &head.inner_rest_hash,
            &head.prev_block_hash,
        );
        self.is_equal(hash, *outcome_proof_block_hash)
    }

    fn ensure_block_hash_matches_outcome_hashed(
        &mut self,
        head_hash: &CryptoHash,
        outcome_proof_block_hash: &CryptoHash,
    ) -> BoolVariable {
        self.is_equal(*head_hash, *outcome_proof_block_hash)
    }

    fn verify_outcome<const OD: usize, const ORD: usize>(
        &mut self,
        expected: &CryptoHash,
        outcome_proof: &MerklePath<OD>,
        outcome_hash: &CryptoHash,
        outcome_root_proof: &MerklePath<ORD>,
    ) -> BoolVariable {
        let outcome_root = self.get_root_from_merkle_proof_hashed_leaf(
            &outcome_proof.path,
            &outcome_proof.indices,
            *outcome_hash,
        );
        let leaf = self.sha256(&outcome_root.0 .0);

        let outcome_root = self.get_root_from_merkle_proof_hashed_leaf(
            &outcome_root_proof.path,
            &outcome_root_proof.indices,
            leaf,
        );
        self.is_equal(outcome_root, *expected)
    }

    fn verify_block<const BD: usize>(
        &mut self,
        expected: &CryptoHash,
        block_proof: &MerklePath<BD>,
        block_hash: &CryptoHash,
    ) -> BoolVariable {
        let block_root = self.get_root_from_merkle_proof_hashed_leaf(
            &block_proof.path,
            &block_proof.indices,
            *block_hash,
        );
        self.is_equal(block_root, *expected)
    }

    fn assertx(&mut self, condition: BoolVariable) {
        let t = self._true();
        self.assert_is_equal(condition, t);
    }

    fn header_hash(
        &mut self,
        inner_lite: &HeaderInner,
        inner_rest_hash: &CryptoHash,
        prev_block_hash: &CryptoHash,
    ) -> CryptoHash {
        let inner_lite_hash = self.inner_lite_hash(&inner_lite);

        let inner = self.sha256_pair(inner_lite_hash, *inner_rest_hash);
        let hash = self.sha256_pair(inner, *prev_block_hash);
        hash
    }

    fn inner_lite_hash(&mut self, inner_lite: &HeaderInner) -> CryptoHash {
        let mut input_stream = VariableStream::new();
        input_stream.write(&inner_lite.height);
        input_stream.write(&inner_lite.epoch_id);
        input_stream.write(&inner_lite.next_epoch_id);
        input_stream.write(&inner_lite.prev_state_root);
        input_stream.write(&inner_lite.outcome_root);
        input_stream.write(&inner_lite.timestamp);
        input_stream.write(&inner_lite.timestamp_nanosec);
        input_stream.write(&inner_lite.next_bp_hash);
        input_stream.write(&inner_lite.block_merkle_root);

        let output_stream = self.hint(input_stream, InnerLiteHash::<40>);
        let hash = output_stream.read::<Bytes32Variable>(self);
        hash
    }
}

pub trait SyncCircuit<L: PlonkParameters<D>, const D: usize> {
    fn sync(&mut self, head: Header, epoch_bps: EpochBlockProducers, next_block: Block);

    fn reconstruct_approval_message(&mut self, next_block: &Block) -> CryptoHash;
}

impl<L: PlonkParameters<D>, const D: usize> SyncCircuit<L, D> for CircuitBuilder<L, D> {
    fn sync(&mut self, head: Header, epoch_bps: EpochBlockProducers, next_block: Block) {
        let mut c = self.ensure_not_already_verified(&head, &next_block.inner_lite.height);
        self.assertx(c);

        c = self.ensure_epoch_is_current_or_next(&head, &next_block.inner_lite.epoch_id);
        self.assertx(c);

        c = self.ensure_if_next_epoch_contains_next_bps(
            &head,
            &next_block.inner_lite.epoch_id,
            &next_block.next_bps,
        );
        self.assertx(c);

        let approval = self.reconstruct_approval_message(&next_block);

        let stake = self.validate_signatures(
            epoch_bps.active,
            next_block.approvals_after_next,
            epoch_bps.bps,
            approval,
        );

        c = self.ensure_stake_is_sufficient(&stake);
        self.assertx(c);

        // TODO: decide what to write here
        // self.evm_write(new_head);
        // self.evm_write(next_block.inner_lite.block_merkle_root);
    }

    fn reconstruct_approval_message(&mut self, next_block: &Block) -> CryptoHash {
        let next_header_hash = self.header_hash(
            &next_block.inner_lite,
            &next_block.inner_rest_hash,
            &next_block.prev_block_hash,
        );

        let next_block_hash = self.sha256_pair(next_block.next_block_inner_hash, next_header_hash);

        let mut input_stream = VariableStream::new();
        input_stream.write(&next_block_hash);
        input_stream.write(&next_block.inner_lite.height);
        let output_stream = self.hint(input_stream, BuildEndorsement::<40>); // TODO: real sizes
        let approval_message = output_stream.read::<Bytes32Variable>(self);

        approval_message
    }
}

pub trait VerifyCircuit<L: PlonkParameters<D>, const D: usize> {
    fn verify(&mut self, proof: Proof);
}

impl<L: PlonkParameters<D>, const D: usize> VerifyCircuit<L, D> for CircuitBuilder<L, D> {
    fn verify(&mut self, proof: Proof) {
        let block_hash = self.header_hash(
            &proof.block_header.inner_lite,
            &proof.block_header.inner_rest_hash,
            &proof.block_header.prev_block_hash,
        );

        let mut c = self.is_equal(block_hash, proof.outcome_proof_block_hash);
        self.assertx(c);

        c = self.verify_outcome(
            &proof.block_header.inner_lite.outcome_root,
            &proof.outcome_proof,
            &proof.outcome_hash,
            &proof.outcome_root_proof,
        );
        self.assertx(c);

        c = self.verify_block(&proof.head_block_root, &proof.block_proof, &block_hash);
        self.assertx(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        
    }
}

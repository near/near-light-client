use crate::merkle::NearMerkleTree;
use crate::variables::{
    BlockHeightVariable, BlockVariable, BuildEndorsement, CryptoHashVariable, HeaderInnerVariable,
    HeaderVariable, InnerLiteHash, MerklePathVariable, ProofVariable, PublicKeyVariable,
    SignatureVariable, StakeInfoVariable, ValidatorStakeVariable, MAX_EPOCH_VALIDATORS,
};
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariable;
use plonky2x::frontend::merkle::tendermint::TendermintMerkleTree;
use plonky2x::prelude::*;

pub trait Verify<L: PlonkParameters<D>, const D: usize> {
    fn ensure_not_already_verified(
        &mut self,
        head: &HeaderVariable,
        block_height: &BlockHeightVariable,
    ) -> BoolVariable;

    fn ensure_epoch_is_current_or_next(
        &mut self,
        head: &HeaderVariable,
        epoch_id: &CryptoHashVariable,
    ) -> BoolVariable;

    fn ensure_if_next_epoch_contains_next_bps(
        &mut self,
        head: &HeaderVariable,
        epoch_id: &CryptoHashVariable,
        next_bps: &ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
    ) -> BoolVariable;

    fn validate_eddsa_signatures(
        &mut self,
        is_active: ArrayVariable<BoolVariable, MAX_EPOCH_VALIDATORS>,
        signatures: ArrayVariable<EDDSASignatureVariable, MAX_EPOCH_VALIDATORS>,
        epoch_bps: ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
        approval_message_hash: Bytes32Variable,
    ) -> StakeInfoVariable;

    fn ensure_stake_is_sufficient(&mut self, stake: &StakeInfoVariable) -> BoolVariable;

    fn ensure_next_bps_is_valid(
        &mut self,
        expected_hash: &CryptoHashVariable,
        next_bps_hash: Option<&CryptoHashVariable>,
    ) -> BoolVariable;

    fn ensure_block_hash_matches_outcome(
        &mut self,
        head: &HeaderVariable,
        outcome_proof_block_hash: &CryptoHashVariable,
    ) -> BoolVariable;

    fn ensure_block_hash_matches_outcome_hashed(
        &mut self,
        head: &CryptoHashVariable,
        outcome_proof_block_hash: &CryptoHashVariable,
    ) -> BoolVariable;

    fn verify_outcome<const OD: usize, const ORD: usize>(
        &mut self,
        expected: &CryptoHashVariable,
        outcome_proof: &MerklePathVariable<OD>,
        outcome_hash: &CryptoHashVariable,
        outcome_root_proof: &MerklePathVariable<ORD>,
    ) -> BoolVariable;

    fn verify_block<const BD: usize>(
        &mut self,
        expected: &CryptoHashVariable,
        block_proof: &MerklePathVariable<BD>,
        block_hash: &CryptoHashVariable,
    ) -> BoolVariable;

    fn header_hash(
        &mut self,
        inner_lite_hash: &HeaderInnerVariable,
        inner_rest_hash: &CryptoHashVariable,
        prev_block_hash: &CryptoHashVariable,
    ) -> CryptoHashVariable;

    fn inner_lite_hash(&mut self, inner_lite: &HeaderInnerVariable) -> CryptoHashVariable;

    fn assertx(&mut self, condition: BoolVariable);
}

impl<L: PlonkParameters<D>, const D: usize> Verify<L, D> for CircuitBuilder<L, D> {
    fn ensure_not_already_verified(
        &mut self,
        head: &HeaderVariable,
        block_height: &BlockHeightVariable,
    ) -> BoolVariable {
        self.gt(*block_height, head.inner_lite.height)
    }

    fn ensure_epoch_is_current_or_next(
        &mut self,
        head: &HeaderVariable,
        epoch_id: &CryptoHashVariable,
    ) -> BoolVariable {
        let epoch = self.is_equal(head.inner_lite.epoch_id, *epoch_id);
        let next_epoch = self.is_equal(head.inner_lite.next_epoch_id, *epoch_id);

        self.or(epoch, next_epoch)
    }

    fn ensure_if_next_epoch_contains_next_bps(
        &mut self,
        head: &HeaderVariable,
        epoch_id: &CryptoHashVariable,
        next_bps: &ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
    ) -> BoolVariable {
        let is_next_epoch = self.is_equal(head.inner_lite.next_epoch_id, *epoch_id);
        let is_not_empty = self.constant(next_bps.len() > 0);
        let ok_anyway = self.constant(true);
        self.select(is_next_epoch, is_not_empty, ok_anyway)
    }

    // TODO: does not build active participants
    fn validate_eddsa_signatures(
        &mut self,
        is_active: ArrayVariable<BoolVariable, MAX_EPOCH_VALIDATORS>,
        signatures: ArrayVariable<EDDSASignatureVariable, MAX_EPOCH_VALIDATORS>,
        epoch_bps: ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
        approval_message_hash: Bytes32Variable,
    ) -> StakeInfoVariable {
        let messages = [approval_message_hash.0; MAX_EPOCH_VALIDATORS];
        let pubkeys: Vec<PublicKeyVariable> = epoch_bps
            .data
            .iter()
            .map(|vs| vs.public_key.clone())
            .collect();

        const MSG_LEN: usize = 32;

        // TODO: switch between eddsa/ecdsa when integrated
        // Here we ensure that all active participants have signed
        self.curta_eddsa_verify_sigs_conditional::<MSG_LEN, MAX_EPOCH_VALIDATORS>(
            is_active.clone(),
            None,
            ArrayVariable::new(messages.to_vec()),
            signatures,
            ArrayVariable::new(pubkeys),
        );

        let mut total_stake = self.constant(0.into());
        let mut approved_stake = self.constant(0.into());

        // Collect all approvals
        for (i, bps) in epoch_bps.data.iter().enumerate() {
            if is_active.data.get(i).is_some() {
                approved_stake = self.add(approved_stake, bps.stake);
            }
            total_stake = self.add(total_stake, bps.stake);
        }

        StakeInfoVariable {
            total_stake,
            approved_stake,
        }
    }

    fn ensure_stake_is_sufficient(&mut self, stake: &StakeInfoVariable) -> BoolVariable {
        let numerator = self.constant(2.into());
        let denominator = self.constant(3.into());

        let threshold = self.mul(stake.total_stake, numerator);
        let approved = self.mul(stake.approved_stake, denominator);
        self.watch(&approved, "approved");
        self.watch(&threshold, "threshold");

        self.gte(approved, threshold)
    }

    fn ensure_next_bps_is_valid(
        &mut self,
        expected_hash: &CryptoHashVariable,
        next_bps_hash: Option<&CryptoHashVariable>,
    ) -> BoolVariable {
        if let Some(next_bps) = next_bps_hash {
            self.is_equal(*next_bps, *expected_hash)
        } else {
            self._true()
        }
    }

    fn ensure_block_hash_matches_outcome(
        &mut self,
        head: &HeaderVariable,
        outcome_proof_block_hash: &CryptoHashVariable,
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
        head_hash: &CryptoHashVariable,
        outcome_proof_block_hash: &CryptoHashVariable,
    ) -> BoolVariable {
        self.is_equal(*head_hash, *outcome_proof_block_hash)
    }

    fn verify_outcome<const OD: usize, const ORD: usize>(
        &mut self,
        expected: &CryptoHashVariable,
        outcome_proof: &MerklePathVariable<OD>,
        outcome_hash: &CryptoHashVariable,
        outcome_root_proof: &MerklePathVariable<ORD>,
    ) -> BoolVariable {
        let outcome_root = self.get_root_from_merkle_proof_hashed_leaf_unindex(
            &outcome_proof.path,
            &outcome_proof.indices,
            *outcome_hash,
        );
        self.watch(&outcome_root, "outcome_proof_root");

        let leaf = self.curta_sha256(&outcome_root.0 .0);
        self.watch(&leaf, "leaf");

        self.watch(outcome_root_proof, "outcome_root_proof");

        let outcome_root = self.get_root_from_merkle_proof_hashed_leaf_unindex(
            &outcome_root_proof.path,
            &outcome_root_proof.indices,
            leaf,
        );
        self.watch(&outcome_root, "outcome_root");
        self.is_equal(outcome_root, *expected)
    }

    fn verify_block<const BD: usize>(
        &mut self,
        expected: &CryptoHashVariable,
        block_proof: &MerklePathVariable<BD>,
        block_hash: &CryptoHashVariable,
    ) -> BoolVariable {
        let block_root = self.get_root_from_merkle_proof_hashed_leaf_unindex(
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
        inner_lite: &HeaderInnerVariable,
        inner_rest_hash: &CryptoHashVariable,
        prev_block_hash: &CryptoHashVariable,
    ) -> CryptoHashVariable {
        let inner_lite_hash = self.inner_lite_hash(&inner_lite);
        let lite_rest = self.curta_sha256_pair(inner_lite_hash, *inner_rest_hash);
        let hash = self.curta_sha256_pair(lite_rest, *prev_block_hash);
        self.watch(&hash, "header_hash");
        hash
    }

    // TODO: convert to hash here
    fn inner_lite_hash(&mut self, inner_lite: &HeaderInnerVariable) -> CryptoHashVariable {
        let mut input_stream = VariableStream::new();
        input_stream.write(&inner_lite.height);
        input_stream.write(&inner_lite.epoch_id);
        input_stream.write(&inner_lite.next_epoch_id);
        input_stream.write(&inner_lite.prev_state_root);
        input_stream.write(&inner_lite.outcome_root);
        input_stream.write(&inner_lite.timestamp);
        input_stream.write(&inner_lite.next_bp_hash);
        input_stream.write(&inner_lite.block_merkle_root);

        let output_stream = self.hint(input_stream, InnerLiteHash::<40>);
        let inner_lite_hash = output_stream.read::<Bytes32Variable>(self);
        self.watch(&inner_lite_hash, "inner_lite_hash");
        inner_lite_hash
    }
}

pub trait SyncCircuit<L: PlonkParameters<D>, const D: usize> {
    fn sync(
        &mut self,
        head: HeaderVariable,
        epoch_bps: ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
        next_block: BlockVariable,
    );

    fn reconstruct_approval_message(&mut self, next_block: &BlockVariable) -> CryptoHashVariable;
}

impl<L: PlonkParameters<D>, const D: usize> SyncCircuit<L, D> for CircuitBuilder<L, D> {
    fn sync(
        &mut self,
        head: HeaderVariable,
        epoch_bps: ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
        next_block: BlockVariable,
    ) {
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

        let signatures_eddsa = next_block
            .approvals_after_next
            .signatures
            .data
            .iter()
            .map(|s| s.ed25519.clone()) // FIXME: when ecdsa
            .collect::<Vec<_>>();

        let stake = self.validate_eddsa_signatures(
            next_block.approvals_after_next.active_bitmask,
            ArrayVariable::new(signatures_eddsa),
            epoch_bps,
            approval,
        );

        c = self.ensure_stake_is_sufficient(&stake);
        self.assertx(c);

        //c = self.ensure_next_bps_is_valid(&head.inner_lite.next_bp_hash, next_block.next_bps)
        // Self::ensure_next_bps_is_valid(
        //                 &next_block.inner_lite.next_bp_hash,
        //                 next_block.next_bps,
        //             )
        //
        // TODO: decide what to write here
        // self.evm_write(new_head);
        // self.evm_write(next_block.inner_lite.block_merkle_root);
    }

    fn reconstruct_approval_message(&mut self, next_block: &BlockVariable) -> CryptoHashVariable {
        let next_header_hash = self.header_hash(
            &next_block.inner_lite,
            &next_block.inner_rest_hash,
            &next_block.prev_block_hash,
        );

        let next_block_hash = self.sha256_pair(next_block.next_block_inner_hash, next_header_hash);

        let mut input_stream = VariableStream::new();
        input_stream.write(&next_block_hash);
        input_stream.write(&next_block.inner_lite.height);
        let output_stream = self.hint(input_stream, BuildEndorsement::<41>);
        let approval_message = output_stream.read::<Bytes32Variable>(self);

        approval_message
    }
}

pub trait VerifyCircuit<L: PlonkParameters<D>, const D: usize> {
    fn verify<const OPD: usize, const ORPD: usize, const BPD: usize>(
        &mut self,
        proof: ProofVariable<OPD, ORPD, BPD>,
    ) -> BoolVariable;
}

impl<L: PlonkParameters<D>, const D: usize> VerifyCircuit<L, D> for CircuitBuilder<L, D> {
    fn verify<const OPD: usize, const ORPD: usize, const BPD: usize>(
        &mut self,
        proof: ProofVariable<OPD, ORPD, BPD>,
    ) -> BoolVariable {
        let block_hash = self.header_hash(
            &proof.block_header.inner_lite,
            &proof.block_header.inner_rest_hash,
            &proof.block_header.prev_block_hash,
        );

        let block_hash_matches = self.is_equal(block_hash, proof.outcome_proof_block_hash);
        self.watch(&block_hash_matches, "block_hash_matches");

        let outcome_matches = self.verify_outcome(
            &proof.block_header.inner_lite.outcome_root,
            &proof.outcome_proof,
            &proof.outcome_hash,
            &proof.outcome_root_proof,
        );
        self.watch(&outcome_matches, "outcome_matches");

        let block_matches =
            self.verify_block(&proof.head_block_root, &proof.block_proof, &block_hash);
        self.watch(&block_matches, "block_matches");

        let verified = self.and(block_matches, outcome_matches);
        let verified = self.and(verified, block_hash_matches);
        self.assertx(verified);
        verified
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::variables::*;
    use near_light_client_protocol::{
        prelude::{BasicProof, Header},
        LightClientBlockView, Proof, StakeInfo, ValidatorStake,
    };
    use near_primitives::{hash::CryptoHash, types::ValidatorStakeV1};
    use serde::de::DeserializeOwned;

    fn fixture<T: DeserializeOwned>(file: &str) -> T {
        serde_json::from_reader(std::fs::File::open(format!("../../fixtures/{}", file)).unwrap())
            .unwrap()
    }
    fn get_next_epoch() -> LightClientBlockView {
        fixture("2.json")
    }

    fn get_first_epoch() -> LightClientBlockView {
        fixture("1.json")
    }

    fn to_header(bv: LightClientBlockView) -> Header {
        Header {
            prev_block_hash: bv.prev_block_hash,
            inner_rest_hash: bv.inner_rest_hash,
            inner_lite: bv.inner_lite,
        }
    }

    fn default_env() {
        let mut builder = DefaultBuilder::new();
        //        let mut pw = PartialWitness::new();
        let x1 = 10;
        let x = builder.init::<U64Variable>();
        //
        // x.set(&mut pw, x1);
        //
        // assert_eq!(x.get(&pw), x1);
        //
        // println!("x1: {:?}", x1.to_le_bytes());
        // println!("x: {:?}", x.encode(&mut builder));
        //
        // let circuit = builder.build();
        // let proof = circuit.data.prove(pw).unwrap();
        // circuit.data.verify(proof).unwrap();
    }

    #[test]
    fn test_header_hash() {
        pretty_env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();
        let header = builder.read::<HeaderVariable>();

        let result = builder.header_hash(
            &header.inner_lite,
            &header.inner_rest_hash,
            &header.prev_block_hash,
        );
        builder.write(result);

        let circuit = builder.build();
        let mut input = circuit.input();

        let header = to_header(fixture("1.json"));
        let expected_hash = header.hash().0;
        println!("expected_hash: {:?}", hex!(expected_hash));

        input.write::<HeaderVariable>(header.into());
        let (_proof, mut output) = circuit.prove(&input);

        let hash = output.read::<CryptoHashVariable>();
        assert_eq!(hash.0, expected_hash);
    }

    // TODO: split humungous test into smaller ones
    #[test]
    fn test_ensures() {
        pretty_env_logger::try_init().unwrap_or_default();
        let test_header = get_first_epoch();
        let test_bps = test_header.next_bps.clone().unwrap_or_default();
        println!("test_bps: {:?}", test_bps.len());
        let test_header = to_header(test_header);

        let mut builder = DefaultBuilder::new();
        let header = builder.read::<HeaderVariable>();

        let early_block_height = builder.constant::<U64Variable>(1);
        let later_block_height = builder.constant::<U64Variable>(test_header.inner_lite.height + 1);

        let r = builder.ensure_not_already_verified(&header, &early_block_height);
        builder.write::<BoolVariable>(r);
        let r = builder.ensure_not_already_verified(&header, &later_block_height);
        builder.write::<BoolVariable>(r);
        let r = builder.ensure_epoch_is_current_or_next(&header, &header.inner_lite.epoch_id);
        builder.write::<BoolVariable>(r);
        let r = builder.ensure_epoch_is_current_or_next(&header, &header.inner_lite.next_epoch_id);
        builder.write::<BoolVariable>(r);

        let next_bps = builder
            .constant::<ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>>(
                test_bps
                    .clone()
                    .into_iter()
                    .map(|s| Into::<ValidatorStake>::into(s))
                    .map(Into::into)
                    .collect(),
            );
        let r = builder.ensure_if_next_epoch_contains_next_bps(
            &header,
            &header.inner_lite.next_epoch_id,
            &next_bps,
        );
        builder.write::<BoolVariable>(r);

        let mut stake = StakeInfo {
            total: 300,
            approved: 200,
        };

        let stake_info = builder.constant::<StakeInfoVariable>(stake.clone().into());
        let stake_is_equal_to_threshold = builder.ensure_stake_is_sufficient(&stake_info);
        builder.write::<BoolVariable>(stake_is_equal_to_threshold);

        stake.approved = 199;
        let stake_info = builder.constant::<StakeInfoVariable>(stake.clone().into());
        let stake_is_less_than_threshold = builder.ensure_stake_is_sufficient(&stake_info);
        builder.write::<BoolVariable>(stake_is_less_than_threshold);

        stake.approved = 201;
        let stake_info = builder.constant::<StakeInfoVariable>(stake.clone().into());
        let stake_is_greater_than_threshold = builder.ensure_stake_is_sufficient(&stake_info);
        builder.write::<BoolVariable>(stake_is_greater_than_threshold);

        stake.approved = 0;
        let stake_info = builder.constant::<StakeInfoVariable>(stake.clone().into());
        let stake_is_zero = builder.ensure_stake_is_sufficient(&stake_info);
        builder.write::<BoolVariable>(stake_is_zero);

        let next_bps_hash = CryptoHash::hash_borsh(test_bps.clone());
        let next_bps_hash = builder.constant::<CryptoHashVariable>(next_bps_hash.0.into());

        let next_bps_is_valid =
            builder.ensure_next_bps_is_valid(&header.inner_lite.next_bp_hash, Some(&next_bps_hash));
        builder.write::<BoolVariable>(next_bps_is_valid);

        let expected_root =
            CryptoHash::from_str("WWrLWbWHwSmjtTn5oBZPYgRCuCYn6fkYVa4yhPWNK4L").unwrap();

        let p: BasicProof = fixture("old.json");
        let outcome_hash = CryptoHash::hash_borsh(p.outcome_proof.to_hashes());
        const OUTCOME_PROOF_AMT: usize = 2;

        let outcome_proof: MerklePathVariableValue<OUTCOME_PROOF_AMT, _> =
            p.outcome_proof.proof.into();
        let outcome_proof =
            builder.constant::<MerklePathVariable<OUTCOME_PROOF_AMT>>(outcome_proof);

        let outcome_root_proof: MerklePathVariableValue<2, _> = p.outcome_root_proof.into();
        let outcome_root_proof = builder.constant::<MerklePathVariable<2>>(outcome_root_proof);

        let expected_outcome_root = builder
            .constant::<CryptoHashVariable>(p.block_header_lite.inner_lite.outcome_root.0.into());
        // outcome_root: "8891c92e4e1106f9433bdec481a50b4d49ea45591e5f829942bc4bd1b1fad6e0"
        // leaf: "4efe13c031019dd7452a42cf735a5edebbe860244ec8539c2cb9ba936dc9ee23"
        // outcome_root: "6b913ffe7a3a776d5f9352281c1e3dca4efcb816d014e69ad2d981c7a3073199"

        let outcome_hash = builder.constant::<CryptoHashVariable>(outcome_hash.0.into());
        let root_matches = builder.verify_outcome(
            &expected_outcome_root,
            &outcome_proof,
            &outcome_hash,
            &outcome_root_proof,
        );
        builder.write::<BoolVariable>(root_matches);

        let expected = builder.constant::<CryptoHashVariable>(expected_root.0.clone().into());

        let block_proof: MerklePathVariableValue<26, _> = p.block_proof.into();
        let block_proof = builder.constant::<MerklePathVariable<26>>(block_proof);
        let block_hash =
            builder.constant::<CryptoHashVariable>(p.block_header_lite.hash().0.into());
        builder.verify_block(&expected, &block_proof, &block_hash);
        builder.write::<BoolVariable>(root_matches);

        let next_bps_hash = CryptoHash::hash_borsh(&test_bps);

        let next_bps_hash = builder.constant::<CryptoHashVariable>(next_bps_hash.0.into());
        let next_bps_hash_matches =
            builder.ensure_next_bps_is_valid(&header.inner_lite.next_bp_hash, Some(&next_bps_hash));
        builder.write::<BoolVariable>(next_bps_hash_matches);

        let registered_p = builder.constant::<ProofVariable<2, 2, 26>>(
            near_light_client_protocol::Proof::Basic {
                head_block_root: expected_root,
                proof: Box::new(fixture("old.json")),
            }
            .into(),
        );
        let proof_verified = builder.verify(registered_p);
        builder.write::<BoolVariable>(proof_verified);

        let circuit = builder.build();
        let mut input = circuit.input();

        input.write::<HeaderVariable>(test_header.into());

        let (proof, mut output) = circuit.prove(&input);

        let height_not_verified = output.read::<BoolVariable>();
        assert!(!height_not_verified, "height was not verified");
        let height_verified = output.read::<BoolVariable>();
        assert!(height_verified, "height was verified");
        let epoch_current = output.read::<BoolVariable>();
        assert!(epoch_current, "epoch was current");
        let epoch_next = output.read::<BoolVariable>();
        assert!(epoch_next, "epoch was next");
        let next_epoch_has_bps = output.read::<BoolVariable>();
        assert!(next_epoch_has_bps, "next epoch has bps");
        let stake_is_equal_to_threshold = output.read::<BoolVariable>();
        assert!(
            stake_is_equal_to_threshold,
            "stake equal to threshold is ok"
        );
        let stake_is_less_than_threshold = output.read::<BoolVariable>();
        assert!(!stake_is_less_than_threshold, "stake less than threshold");
        let stake_is_greater_than_threshold = output.read::<BoolVariable>();
        assert!(
            stake_is_greater_than_threshold,
            "stake greater than threshold"
        );
        let stake_is_zero = output.read::<BoolVariable>();
        assert!(!stake_is_zero, "stake is zero");
        let next_bps_is_valid = output.read::<BoolVariable>();
        assert!(next_bps_is_valid, "next bps is valid");
        let outcome_root_matches = output.read::<BoolVariable>();
        assert!(outcome_root_matches);
        let block_root_matches = output.read::<BoolVariable>();
        assert!(block_root_matches);
        let next_bps_hash_matches = output.read::<BoolVariable>();
        assert!(next_bps_hash_matches);
        let proof_verified = output.read::<BoolVariable>();
        assert!(proof_verified);
    }

    #[test]
    fn test_reconstruct_approval_msg() {}
}

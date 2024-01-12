use crate::merkle::NearMerkleTree;
use crate::variables::{
    BlockHeightVariable, BlockVariable, BuildEndorsement, CryptoHashVariable, HeaderInnerVariable,
    HeaderVariable, InnerLiteHash, MerklePathVariable, ProofVariable, PublicKeyVariable,
    StakeInfoVariable, ValidatorStakeVariable, MAX_EPOCH_VALIDATORS,
};
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariable;
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
        approval_message_hash: BytesVariable<41>,
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
        let ok_anyway = self._true();
        self.select(is_next_epoch, is_not_empty, ok_anyway)
    }


    // TODO: does not build active participants
    fn validate_eddsa_signatures(
        &mut self,
        is_active: ArrayVariable<BoolVariable, MAX_EPOCH_VALIDATORS>,
        signatures: ArrayVariable<EDDSASignatureVariable, MAX_EPOCH_VALIDATORS>,
        epoch_bps: ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
        approval_message: BytesVariable<41>,
    ) -> StakeInfoVariable {
        let messages = [approval_message.0; MAX_EPOCH_VALIDATORS];
        let pubkeys: Vec<PublicKeyVariable> = epoch_bps
            .data
            .iter()
            .map(|vs| vs.public_key.clone())
            .collect();

        const MSG_LEN: usize = 41;

        // TODO: switch between eddsa/ecdsa when integrated
        // Here we ensure that all active participants have signed
        self.curta_eddsa_verify_sigs_conditional::<MSG_LEN, MAX_EPOCH_VALIDATORS>(
            is_active.clone(),
            None,
            ArrayVariable::new(messages.to_vec()),
            signatures,
            ArrayVariable::new(pubkeys),
        );

        let mut total_stake = self.zero();
        let mut approved_stake = self.zero();

        // Collect all approvals
        for (i, bps) in epoch_bps.data.iter().enumerate() {
            if is_active.data.get(i).is_some() {
                approved_stake = self.add(approved_stake, bps.stake);
            }
            total_stake = self.add(total_stake, bps.stake);
        }

        StakeInfoVariable {
            total: total_stake,
            approved: approved_stake,
        }
    }

    fn ensure_stake_is_sufficient(&mut self, stake: &StakeInfoVariable) -> BoolVariable {
        let numerator = self.constant(2.into());
        let denominator = self.constant(3.into());

        let threshold = self.mul(stake.total, numerator);
        let approved = self.mul(stake.approved, denominator);
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

        let output_bytes = self.hint(input_stream, InnerLiteHash::<208>);
        let inner_lite_bytes = output_bytes.read::<BytesVariable<208>>(self);
        self.watch(&inner_lite_bytes, "inner_lite_bytes");

        let inner_lite_hash = self.curta_sha256(&inner_lite_bytes.0);
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

    fn reconstruct_approval_message(&mut self, next_block: &BlockVariable) -> BytesVariable<41>;
}

impl<L: PlonkParameters<D>, const D: usize> SyncCircuit<L, D> for CircuitBuilder<L, D> {
    fn sync(
        &mut self,
        head: HeaderVariable,
        epoch_bps: ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
        next_block: BlockVariable,
    ) {
        let a = self.ensure_not_already_verified(&head, &next_block.inner_lite.height);
        //self.assertx(a);

        let b = self.ensure_epoch_is_current_or_next(&head, &next_block.inner_lite.epoch_id);
        //self.assertx(b);

        let c = self.ensure_if_next_epoch_contains_next_bps(
            &head,
            &next_block.inner_lite.epoch_id,
            &next_block.next_bps,
        );
        self.assertx(c);

        let new_head = HeaderVariable {
            prev_block_hash: next_block.prev_block_hash,
            inner_rest_hash: next_block.inner_rest_hash,
            inner_lite: next_block.inner_lite.clone(),
        };
        self.watch(&new_head, "new_head");

        let approval = self.reconstruct_approval_message(&next_block);
        self.watch(&approval, "approval_msg");

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
        self.watch(&stake, "stake");

        let d = self.ensure_stake_is_sufficient(&stake);
        //self.assertx(d);

        //c = self.ensure_next_bps_is_valid(&head.inner_lite.next_bp_hash, next_block.next_bps)
        // Self::ensure_next_bps_is_valid(
        //                 &next_block.inner_lite.next_bp_hash,
        //                 next_block.next_bps,
        //             )
        //
        // TODO: decide what to write here for evm
        self.write(new_head);
        // self.evm_write(next_block.inner_lite.block_merkle_root);
    }

    // TODO: make const fn here to test len with real approval
    fn reconstruct_approval_message(&mut self, next_block: &BlockVariable) -> BytesVariable<41> {
        let next_header_hash = self.header_hash(
            &next_block.inner_lite,
            &next_block.inner_rest_hash,
            &next_block.prev_block_hash,
        );

        let next_block_hash =
            self.curta_sha256_pair(next_block.next_block_inner_hash, next_header_hash);

        let mut input_stream = VariableStream::new();
        input_stream.write(&next_block_hash);
        input_stream.write(&next_block.inner_lite.height);
        let output_stream = self.hint(input_stream, BuildEndorsement::<41>);
        let approval_message = output_stream.read::<BytesVariable<41>>(self);
        self.watch(&approval_message, "approval_message");
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
        EpochId, LightClientBlockView, Proof, Protocol, StakeInfo, ValidatorStake,
    };
    use near_primitives::{hash::CryptoHash, types::ValidatorStakeV1};
    use plonky2x::backend::circuit::{PublicInput, PublicOutput};
    use serde::de::DeserializeOwned;

    type B<const D: usize = 2> = CircuitBuilder<DefaultParameters, D>;
    type PI<const D: usize = 2> = PublicInput<DefaultParameters, D>;
    type PO<const D: usize = 2> = PublicOutput<DefaultParameters, D>;

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
    fn to_header(bv: LightClientBlockView) -> Header {
        Header {
            prev_block_hash: bv.prev_block_hash,
            inner_rest_hash: bv.inner_rest_hash,
            inner_lite: bv.inner_lite,
        }
    }

    // TODO: define inputs and logic at once
    fn builder_suite<F, WriteInputs, Assertions>(
        define: F,
        writer: WriteInputs,
        assertions: Assertions,
    ) where
        F: FnOnce(&mut B),
        WriteInputs: FnOnce(&mut PI),
        Assertions: FnOnce(PO),
    {
        pretty_env_logger::try_init().unwrap_or_default();

        let mut builder = B::new();
        define(&mut builder);

        let circuit = builder.build();

        let mut inputs = circuit.input();
        writer(&mut inputs);

        let (proof, output) = circuit.prove(&inputs);

        assertions(output.clone());

        circuit.verify(&proof, &inputs, &output);
    }

    #[test]
    fn test_header_hash() {
        let header = to_header(fixture("1.json"));
        let expected_hash = header.hash().0;

        let define = |builder: &mut B| {
            let header = builder.read::<HeaderVariable>();
            let result = builder.header_hash(
                &header.inner_lite,
                &header.inner_rest_hash,
                &header.prev_block_hash,
            );
            builder.write(result);
        };

        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(header.into());
        };

        let assertions = |mut output: PO| {
            let hash = output.read::<CryptoHashVariable>();
            assert_eq!(hash.0, expected_hash);
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_stake() {
        let approved_stakes = [200, 199, 201, 0];

        let define = |builder: &mut B| {
            let mut stake_info = builder.constant::<StakeInfoVariable>(
                StakeInfo {
                    total: 300,
                    approved: 0,
                }
                .into(),
            );

            for _ in 0..approved_stakes.len() {
                stake_info.approved = builder.read::<BalanceVariable>();
                let is_sufficient = builder.ensure_stake_is_sufficient(&stake_info);
                builder.write::<BoolVariable>(is_sufficient);
            }
        };
        let writer = |input: &mut PI| {
            for stake in approved_stakes {
                input.write::<BalanceVariable>(stake.into());
            }
        };
        let assertions = |mut output: PO| {
            assert!(output.read::<BoolVariable>(), "stake is equal to threshold");
            assert!(
                !output.read::<BoolVariable>(),
                "stake is less than threshold"
            );
            assert!(
                output.read::<BoolVariable>(),
                "stake is greater than threshold"
            );
            assert!(!output.read::<BoolVariable>(), "stake is zero");
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_ensure_height() {
        let test_header = to_header(get_first_epoch());
        let define = |builder: &mut B| {
            let header = builder.read::<HeaderVariable>();

            let early_block_height = builder.constant::<U64Variable>(1);
            let one = builder.one();
            let later_block_height = builder.add(header.inner_lite.height, one);

            let r = builder.ensure_not_already_verified(&header, &early_block_height);
            builder.write::<BoolVariable>(r);

            let r = builder.ensure_not_already_verified(&header, &later_block_height);
            builder.write::<BoolVariable>(r);
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(test_header.into());
        };
        let assertions = |mut output: PO| {
            assert!(!output.read::<BoolVariable>(), "too early");
            assert!(output.read::<BoolVariable>(), "height is later");
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_ensure_next_bps() {
        let header = get_first_epoch();
        let bps = header.next_bps.clone().unwrap_or_default();
        let bps_hash = CryptoHash::hash_borsh(bps.clone());
        let header = to_header(header);

        let define = |builder: &mut B| {
            let header = builder.read::<HeaderVariable>();
            let next_bps =
                builder.read::<ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>>();

            let current =
                builder.ensure_epoch_is_current_or_next(&header, &header.inner_lite.epoch_id);
            builder.write::<BoolVariable>(current);
            let next =
                builder.ensure_epoch_is_current_or_next(&header, &header.inner_lite.next_epoch_id);
            builder.write::<BoolVariable>(next);

            let contains_next_bps = builder.ensure_if_next_epoch_contains_next_bps(
                &header,
                &header.inner_lite.next_epoch_id,
                &next_bps,
            );
            builder.write::<BoolVariable>(contains_next_bps);

            let next_bps_hash = builder.constant::<CryptoHashVariable>(bps_hash.0.into());
            let is_valid = builder
                .ensure_next_bps_is_valid(&header.inner_lite.next_bp_hash, Some(&next_bps_hash));
            builder.write::<BoolVariable>(is_valid);
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(header.into());
            input.write::<ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>>(
                bps.clone()
                    .into_iter()
                    .map(|s| Into::<ValidatorStake>::into(s))
                    .map(Into::into)
                    .collect(),
            )
        };
        let assertions = |mut output: PO| {
            assert!(output.read::<BoolVariable>(), "epoch is current");
            assert!(output.read::<BoolVariable>(), "epoch is next");
            assert!(output.read::<BoolVariable>(), "next epoch has bps");
            assert!(output.read::<BoolVariable>(), "next bps is valid");
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_ensure_proofs() {
        let block_root =
            CryptoHash::from_str("WWrLWbWHwSmjtTn5oBZPYgRCuCYn6fkYVa4yhPWNK4L").unwrap();
        let p: BasicProof = fixture("old.json");
        let outcome_hash = CryptoHash::hash_borsh(p.outcome_proof.to_hashes());

        const OUTCOME_PROOF_AMT: usize = 2;
        const OUTCOME_ROOT_PROOF_AMT: usize = 2;
        const BLOCK_PROOF_AMT: usize = 26;

        let define = |builder: &mut B| {
            let proof = builder.read::<ProofVariable<
                OUTCOME_PROOF_AMT,
                OUTCOME_ROOT_PROOF_AMT,
                BLOCK_PROOF_AMT,
            >>();
            let expected_outcome_root = builder.read::<CryptoHashVariable>();
            let expected_block_root = builder.read::<CryptoHashVariable>();

            // TODO: to_hashes
            let outcome_hash = builder.constant::<CryptoHashVariable>(outcome_hash.0.into());
            let root_matches = builder.verify_outcome(
                &expected_outcome_root,
                &proof.outcome_proof,
                &outcome_hash,
                &proof.outcome_root_proof,
            );
            builder.write::<BoolVariable>(root_matches);

            // TODO: to_hashes
            let block_hash =
                builder.constant::<CryptoHashVariable>(p.block_header_lite.hash().0.into());
            let root_matches =
                builder.verify_block(&expected_block_root, &proof.block_proof, &block_hash);
            builder.write::<BoolVariable>(root_matches);

            let proof_verified = builder.verify(proof);
            builder.write::<BoolVariable>(proof_verified);
        };
        let writer = |input: &mut PI| {
            input
                .write::<ProofVariable<OUTCOME_PROOF_AMT, OUTCOME_ROOT_PROOF_AMT, BLOCK_PROOF_AMT>>(
                    near_light_client_protocol::Proof::Basic {
                        head_block_root: block_root,
                        proof: Box::new(fixture("old.json")),
                    }
                    .into(),
                );
            input.write::<CryptoHashVariable>(p.block_header_lite.inner_lite.outcome_root.0.into());
            input.write::<CryptoHashVariable>(block_root.0.clone().into());
        };
        let assertions = |mut output: PO| {
            assert!(output.read::<BoolVariable>(), "outcome root matches");
            assert!(output.read::<BoolVariable>(), "block root matches");
            assert!(output.read::<BoolVariable>(), "proof verified");
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_inclusion_proof_blackbox() {
        let block_root =
            CryptoHash::from_str("WWrLWbWHwSmjtTn5oBZPYgRCuCYn6fkYVa4yhPWNK4L").unwrap();

        const OUTCOME_PROOF_AMT: usize = 2;
        const OUTCOME_ROOT_PROOF_AMT: usize = 2;
        const BLOCK_PROOF_AMT: usize = 26;

        let define = |builder: &mut B| {
            let registered_proof = builder.read::<ProofVariable<
                OUTCOME_PROOF_AMT,
                OUTCOME_ROOT_PROOF_AMT,
                BLOCK_PROOF_AMT,
            >>();

            let proof_verified = builder.verify(registered_proof);
            builder.write::<BoolVariable>(proof_verified);
        };
        let writer = |input: &mut PI| {
            input
                .write::<ProofVariable<OUTCOME_PROOF_AMT, OUTCOME_ROOT_PROOF_AMT, BLOCK_PROOF_AMT>>(
                    near_light_client_protocol::Proof::Basic {
                        head_block_root: block_root,
                        proof: Box::new(fixture("old.json")),
                    }
                    .into(),
                );
        };
        let assertions = |mut output: PO| {
            assert!(output.read::<BoolVariable>(), "proof verified");
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_sync_accross_boundaries_blackbox() {
        pretty_env_logger::try_init().unwrap_or_default();
        let (head, next_bps, next_block) = test_state();

        let define = |builder: &mut B| {
            let header = builder.read::<HeaderVariable>();
            let bps = builder.read::<ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>>();
            let next_block = builder.read::<BlockVariable>();
            builder.sync(header, bps, next_block);
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(head.into());
            input.write::<ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>>(
                next_bps
                    .clone()
                    .into_iter()
                    .map(|s| Into::<ValidatorStake>::into(s))
                    .map(Into::into)
                    .collect(),
            );
            input.write::<BlockVariable>(next_block.clone().into());
        };
        let assertions = |mut output: PO| {
            let header = output.read::<HeaderVariable>();
            println!("header: {:?}", header);
        };
        builder_suite(define, writer, assertions);

        // let mut sync_and_update = |next_block: LightClientBlockView| {
        //     let next_bps = builder
        //         .constant::<ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>>(
        //             bps_var
        //                 .clone()
        //                 .into_iter()
        //                 .map(|s| Into::<ValidatorStake>::into(s))
        //                 .map(Into::into)
        //                 .collect(),
        //         );
        //     let next_block = builder.constant::<BlockVariable>(next_block.clone().into());
        //     //     // Assert we matched the epoch id for the new BPS
        //     //     assert_eq!(
        //     //         head.inner_lite.next_epoch_id,
        //     //         sync_next.next_bps.as_ref().unwrap().0 .0
        //     //     );
        //     //
        //     //     head = sync_next.new_head;
        //     //     next_bps = sync_next.next_bps.unwrap().1;
        //     //
        //     //     // Assert new head is the new block
        //     //     assert_eq!(head.inner_lite, next_block.inner_lite);
        //     //     // Assert new BPS is from the next block producers because we're
        //     //     // in an epoch boundary
        //     //     assert_eq!(
        //     //         &next_bps,
        //     //         &next_block
        //     //             .next_bps
        //     //             .unwrap()
        //     //             .into_iter()
        //     //             .map(Into::into)
        //     //             .collect_vec()
        //     //     );
        //     //     next_epoch_id.0 = head.inner_lite.next_epoch_id;
        // };
        // sync_and_update(next_block_var.clone());
        //
    }

    #[test]
    fn test_reconstruct_approval_msg() {
        pretty_env_logger::try_init().unwrap_or_default();
        let (_, next_bps, next_block) = test_state();
        println!(
            "bps len {} sigs len {} next len {}",
            next_bps.len(),
            next_block.approvals_after_next.len(),
            next_block.next_bps.as_ref().unwrap().len()
        );

        let define = |builder: &mut B| {
            let next_block = builder.read::<BlockVariable>();
            let os = builder.reconstruct_approval_message(&next_block);
            builder.write::<BytesVariable<41>>(os);
        };
        let writer = |input: &mut PI| {
            input.write::<BlockVariable>(next_block.clone().into());
        };
        let assertions = |mut output: PO| {
            let msghash = output.read::<BytesVariable<41>>();
            let msg = Protocol::reconstruct_approval_message(&next_block).unwrap();
            assert_eq!(msghash, msghash);
            println!("msg: {:?}", msg);
        };
        builder_suite(define, writer, assertions);
    }
}

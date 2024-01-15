use crate::merkle::NearMerkleTree;
use crate::variables::{
    ApprovalMessage, BlockHeightVariable, BlockVariable, BpsApprovals, BpsArr, BuildEndorsement,
    CryptoHashVariable, HeaderVariable, MerklePathVariable, ProofVariable, StakeInfoVariable,
    ValidatorStakeVariable,
};
use plonky2x::prelude::plonky2::plonk::config::GenericHashOut;
use plonky2x::prelude::*;
use pretty_assertions::assert_eq;

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
        next_bps: &BpsArr<ValidatorStakeVariable>,
    ) -> BoolVariable;

    fn validate_signatures<const LEN: usize>(
        &mut self,
        approvals: BpsApprovals<LEN>,
        bps: BpsArr<ValidatorStakeVariable, LEN>,
        approval_message: ApprovalMessage,
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
        next_bps: &BpsArr<ValidatorStakeVariable>,
    ) -> BoolVariable {
        let is_next_epoch = self.is_equal(head.inner_lite.next_epoch_id, *epoch_id);
        let is_not_empty = self.constant(next_bps.len() > 0);
        let ok_anyway = self._true();
        self.select(is_next_epoch, is_not_empty, ok_anyway)
    }

    fn validate_signatures<const LEN: usize>(
        &mut self,
        approvals_after_next: BpsApprovals<LEN>,
        epoch_bps: BpsArr<ValidatorStakeVariable, LEN>,
        approval_message: ApprovalMessage,
    ) -> StakeInfoVariable {
        assert_eq!(approvals_after_next.is_active.len(), LEN);
        assert_eq!(approvals_after_next.signatures.len(), LEN);
        assert_eq!(epoch_bps.data.len(), LEN);

        let messages = [approval_message; LEN];

        let mut pubkeys = vec![];
        let mut total_stake = self.zero();
        let mut approved_stake = self.zero();

        for i in 0..LEN {
            let vs = &epoch_bps.data[i];

            pubkeys.push(vs.public_key.clone());

            let maybe_add = self.add(approved_stake, vs.stake);
            approved_stake =
                self.select(approvals_after_next.is_active[i], maybe_add, approved_stake);
            total_stake = self.add(total_stake, vs.stake);
        }

        self.curta_eddsa_verify_sigs_conditional(
            approvals_after_next.is_active.clone(),
            None,
            ArrayVariable::new(messages.to_vec()),
            approvals_after_next.signatures,
            ArrayVariable::new(pubkeys),
        );

        StakeInfoVariable {
            total: total_stake,
            approved: approved_stake,
        }
    }

    fn ensure_stake_is_sufficient(&mut self, stake: &StakeInfoVariable) -> BoolVariable {
        // 2/3 stake
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
        let hash = head.hash(self);
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
        self.watch(&leaf, "outcome_leaf");

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
}

pub trait SyncCircuit<L: PlonkParameters<D>, const D: usize> {
    fn sync(
        &mut self,
        head: HeaderVariable,
        epoch_bps: BpsArr<ValidatorStakeVariable>,
        next_block: BlockVariable,
    );

    fn reconstruct_approval_message(&mut self, next_block: &BlockVariable) -> ApprovalMessage;
}

impl<L: PlonkParameters<D>, const D: usize> SyncCircuit<L, D> for CircuitBuilder<L, D> {
    fn sync(
        &mut self,
        head: HeaderVariable,
        epoch_bps: BpsArr<ValidatorStakeVariable>,
        next_block: BlockVariable,
    ) {
        let a = self.ensure_not_already_verified(&head, &next_block.header.inner_lite.height);
        self.assertx(a);

        let b = self.ensure_epoch_is_current_or_next(&head, &next_block.header.inner_lite.epoch_id);
        self.assertx(b);

        let c = self.ensure_if_next_epoch_contains_next_bps(
            &head,
            &next_block.header.inner_lite.epoch_id,
            &next_block.next_bps,
        );
        self.assertx(c);

        let approval = self.reconstruct_approval_message(&next_block);

        let stake = self.validate_signatures(next_block.approvals_after_next, epoch_bps, approval);

        let d = self.ensure_stake_is_sufficient(&stake);
        self.assertx(d);

        // TODO: hashing bps
        // if next_block.next_bps.len() > 0 {
        // let c = self.ensure_next_bps_is_valid(
        //     &head.inner_lite.next_bp_hash,
        //     Some(&next_block.next_bps),
        // );
        // self.assertx(c);
        // self.write::<BpsArr<ValidatorStakeVariable>>(next_block.next_bps);
        //}
        self.watch(&next_block.header, "new_head");
        self.write::<HeaderVariable>(next_block.header);
        // TODO: decide what to write here for evm
        // self.evm_write(next_block.inner_lite.block_merkle_root);
    }

    // TODO: make const fn here to test len with real approval
    fn reconstruct_approval_message(&mut self, next_block: &BlockVariable) -> ApprovalMessage {
        let next_header_hash = next_block.header.hash(self);
        let next_block_hash =
            self.curta_sha256_pair(next_block.next_block_inner_hash, next_header_hash);

        let mut input_stream = VariableStream::new();
        input_stream.write(&next_block_hash);
        input_stream.write(&next_block.header.inner_lite.height);

        let output_stream = self.hint(input_stream, BuildEndorsement);

        let msg = output_stream.read::<ApprovalMessage>(self);
        self.watch(&msg, "approval_message");
        msg
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
        let block_hash = proof.block_header.hash(self);

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

        let comp = self.and(block_matches, outcome_matches);
        let verified = self.and(comp, block_hash_matches);
        self.assertx(verified);
        verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::variables::*;
    use near_light_client_protocol::{
        prelude::{BasicProof, Header, Itertools},
        LightClientBlockView, Proof, Protocol, StakeInfo, ValidatorStake,
    };
    use near_primitives::hash::CryptoHash;
    use plonky2x::frontend::{
        ecc::curve25519::ed25519::eddsa::EDDSASignatureVariable, vars::EvmVariable,
    };
    use plonky2x::{
        backend::circuit::{PublicInput, PublicOutput},
        frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariableValue,
    };
    use pretty_assertions::{assert_eq, assert_ne};
    use serde::de::DeserializeOwned;
    use std::str::FromStr;

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
            let result = header.hash(builder);
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
            let next_bps = builder.read::<BpsArr<ValidatorStakeVariable>>();

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
            input.write::<HeaderVariable>(header.clone().into());
            input.write::<BpsArr<ValidatorStakeVariable>>(bps_to_variable(Some(bps)));
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
    fn test_sync_across_boundaries_blackbox() {
        let (head, next_bps, next_block) = test_state();

        let define = |builder: &mut B| {
            let header = builder.read::<HeaderVariable>();
            let bps = builder.read::<BpsArr<ValidatorStakeVariable>>();
            let next_block = builder.read::<BlockVariable>();
            builder.sync(header, bps, next_block);
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(head.into());
            input.write::<BpsArr<ValidatorStakeVariable>>(bps_to_variable(Some(next_bps)));
            input.write::<BlockVariable>(next_block.clone().into());
        };
        let assertions = |mut output: PO| {
            let header = output.read::<HeaderVariable>();
            println!("header: {:?}", header);
        };
        builder_suite(define, writer, assertions);

        // TODO: let mut sync_and_update = |next_block: LightClientBlockView| {
        //     let next_bps = builder
        //         .constant::<BpsArr<ValidatorStakeVariable>>(
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
    fn test_bounded_signatures() {
        let (_, bps, next_block) = test_state();
        const BPS_AMT: usize = 5;

        let define = |builder: &mut B| {
            let bps = builder.read::<BpsArr<ValidatorStakeVariable, BPS_AMT>>();
            let next_block = builder.read::<BlockVariable>();

            let next_block_approvals = BpsApprovals {
                signatures: next_block.approvals_after_next.signatures[0..BPS_AMT]
                    .to_vec()
                    .into(),
                is_active: next_block.approvals_after_next.is_active[0..BPS_AMT]
                    .to_vec()
                    .into(),
            };

            let msg = builder.reconstruct_approval_message(&next_block);

            builder.validate_signatures(next_block_approvals, bps, msg);
        };
        let writer = |input: &mut PI| {
            input.write::<BpsArr<ValidatorStakeVariable, BPS_AMT>>(
                bps_to_variable(Some(bps.clone()))[0..BPS_AMT].into(),
            );
            input.write::<BlockVariable>(next_block.into());
        };
        let assertions = |mut _output: PO| {};
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_reconstruct_approval_msg() {
        let (_, _, next_block) = test_state();
        let define = |builder: &mut B| {
            let next_block = builder.read::<BlockVariable>();
            let os = builder.reconstruct_approval_message(&next_block);
            builder.write::<ApprovalMessage>(os);
        };
        let writer = |input: &mut PI| {
            input.write::<BlockVariable>(next_block.clone().into());
        };
        let assertions = |mut output: PO| {
            let created = output.read::<ApprovalMessage>();
            let msg = Protocol::reconstruct_approval_message(&next_block).unwrap();
            assert_eq!(msg, created);
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    fn test_raw_le_bytes() {
        let (_, _, next_block) = test_state();
        let define = |builder: &mut B| {
            let next_block = builder.read::<BlockVariable>();
            let height_bits = next_block.header.inner_lite.height.to_le_bits(builder);
            let bytes = height_bits
                .chunks(8)
                .map(|chunk| ByteVariable(chunk.try_into().unwrap()))
                .collect_vec();
            builder.write::<BytesVariable<8>>(BytesVariable(bytes.try_into().unwrap()));
        };
        let writer = |input: &mut PI| {
            input.write::<BlockVariable>(next_block.clone().into());
        };
        let assertions = |mut output: PO| {
            let bytes = output.read::<BytesVariable<8>>();
            assert_eq!(bytes, next_block.inner_lite.height.to_le_bytes());
        };
        builder_suite(define, writer, assertions);
    }
}

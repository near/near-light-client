use near_light_client_primitives::NUM_BLOCK_PRODUCER_SEATS;
use near_light_client_protocol::prelude::Itertools;
use plonky2x::{
    frontend::{
        curta::ec::point::CompressedEdwardsY, ecc::curve25519::ed25519::eddsa::DUMMY_PUBLIC_KEY,
    },
    prelude::*,
};
use pretty_assertions::assert_eq;

use crate::{
    merkle::{MerklePathVariable, NearMerkleTree},
    variables::{
        ApprovalMessage, BlockHeightVariable, BlockVariable, BpsApprovals, BpsArr,
        BuildEndorsement, CryptoHashVariable, HeaderVariable, ProofVariable, PublicKeyVariable,
        StakeInfoVariable, ValidatorStakeVariable,
    },
};

pub trait Ensure<L: PlonkParameters<D>, const D: usize> {
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
        approvals: &BpsApprovals<LEN>,
        bps: &BpsArr<ValidatorStakeVariable, LEN>,
        approval_message: ApprovalMessage,
    ) -> StakeInfoVariable;

    fn ensure_stake_is_sufficient(&mut self, stake: &StakeInfoVariable) -> BoolVariable;

    fn ensure_next_bps_is_valid(
        &mut self,
        expected_hash: &CryptoHashVariable,
        next_bps_hash: &CryptoHashVariable,
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

impl<L: PlonkParameters<D>, const D: usize> Ensure<L, D> for CircuitBuilder<L, D> {
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
        let epoch_id = *epoch_id;
        let this = self.is_equal(epoch_id, head.inner_lite.epoch_id);
        let next = self.is_equal(epoch_id, head.inner_lite.next_epoch_id);
        self.or(this, next)
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
        approvals_after_next: &BpsApprovals<LEN>,
        epoch_bps: &BpsArr<ValidatorStakeVariable, LEN>,
        approval_message: ApprovalMessage,
    ) -> StakeInfoVariable {
        assert_eq!(approvals_after_next.is_active.len(), LEN);
        assert_eq!(approvals_after_next.signatures.len(), LEN);
        assert_eq!(epoch_bps.data.len(), LEN);

        let messages = [approval_message; LEN];

        let dummy_pk = self.constant::<PublicKeyVariable>(CompressedEdwardsY(DUMMY_PUBLIC_KEY));
        let inactive = self._false();

        let mut pubkeys = vec![];
        let mut active = vec![];
        let mut total_stake = self.zero();
        let mut approved_stake = self.zero();

        for i in 0..LEN {
            let vs = &epoch_bps.data[i];

            let is_dummy = self.is_equal(dummy_pk.clone(), vs.public_key.clone());
            let sig_active = approvals_after_next.is_active[i];
            let is_active = self.select(is_dummy, inactive, sig_active);

            pubkeys.push(vs.public_key.clone());
            active.push(is_active.clone());

            let added_stake = self.add(approved_stake, vs.stake);
            total_stake = self.add(total_stake, vs.stake);
            approved_stake = self.select(is_active, added_stake, approved_stake);
        }

        // TODO: what happens if a conditionally active signature fails?
        self.curta_eddsa_verify_sigs_conditional(
            ArrayVariable::new(active),
            None,
            ArrayVariable::new(messages.to_vec()),
            approvals_after_next.signatures.clone(),
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
        self.gte(approved, threshold)
    }

    fn ensure_next_bps_is_valid(
        &mut self,
        expected_hash: &CryptoHashVariable,
        next_bps_hash: &CryptoHashVariable,
    ) -> BoolVariable {
        let zeroed = self.constant::<CryptoHashVariable>([0u8; 32].into());

        let is_empty = self.is_equal(*next_bps_hash, zeroed);
        let is_valid = self.is_equal(*next_bps_hash, *expected_hash);
        let ok_anyway = self._true();

        self.select(is_empty, ok_anyway, is_valid)
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

        let leaf = self.curta_sha256(&outcome_root.0 .0);

        let outcome_root = self.get_root_from_merkle_proof_hashed_leaf_unindex(
            &outcome_root_proof.path,
            &outcome_root_proof.indices,
            leaf,
        );
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

pub trait Sync<L: PlonkParameters<D>, const D: usize> {
    fn sync(
        &mut self,
        head: &HeaderVariable,
        epoch_bps: &BpsArr<ValidatorStakeVariable>,
        next_block: &BlockVariable,
    ) -> HeaderVariable;

    fn reconstruct_approval_message(&mut self, next_block: &BlockVariable) -> ApprovalMessage;
}

impl<L: PlonkParameters<D>, const D: usize> Sync<L, D> for CircuitBuilder<L, D> {
    fn sync(
        &mut self,
        head: &HeaderVariable,
        epoch_bps: &BpsArr<ValidatorStakeVariable>,
        next_block: &BlockVariable,
    ) -> HeaderVariable {
        let not_verified =
            self.ensure_not_already_verified(head, &next_block.header.inner_lite.height);
        self.watch(&not_verified, "ensure_not_already_verified");

        let valid_epoch =
            self.ensure_epoch_is_current_or_next(head, &next_block.header.inner_lite.epoch_id);
        self.watch(&valid_epoch, "ensure_epoch_is_current_or_next");

        let has_bps = self.ensure_if_next_epoch_contains_next_bps(
            head,
            &next_block.header.inner_lite.epoch_id,
            &next_block.next_bps,
        );
        self.watch(&has_bps, "ensure_if_next_epoch_contains_next_bps");

        let approval = self.reconstruct_approval_message(next_block);
        self.watch(&approval, "reconstruct_approval_message");
        let stake = self.validate_signatures(&next_block.approvals_after_next, epoch_bps, approval);
        self.watch(&stake, "validate_signatures");
        let enough_stake = self.ensure_stake_is_sufficient(&stake);
        self.watch(&enough_stake, "ensure_stake_is_sufficient");

        let x = self.and(not_verified, valid_epoch);
        let y = self.and(has_bps, enough_stake);
        let all = self.and(x, y);
        self.watch(&all, "all");
        self.assertx(all);

        // TODO: test me
        let bps_valid = self.ensure_next_bps_is_valid(
            &next_block.header.inner_lite.next_bp_hash,
            &next_block.next_bps_hash,
        );
        self.assertx(bps_valid);
        assert!(next_block.next_bps.len() == NUM_BLOCK_PRODUCER_SEATS);

        next_block.header.to_owned()
    }

    fn reconstruct_approval_message(&mut self, next_block: &BlockVariable) -> ApprovalMessage {
        let next_header_hash = next_block.header.hash(self);
        let next_block_hash =
            self.curta_sha256_pair(next_block.next_block_inner_hash, next_header_hash);

        let should_hint = false;
        // TODO: decide if we should constrain this way or just hint in the manual
        // encodes
        if should_hint {
            let mut input_stream = VariableStream::new();
            input_stream.write(&next_block_hash);
            input_stream.write(&next_block.header.inner_lite.height);
            let output_stream = self.hint(input_stream, BuildEndorsement);
            output_stream.read::<ApprovalMessage>(self)
        } else {
            let mut bytes = vec![ByteVariable::zero(self)];
            bytes.extend_from_slice(&next_block_hash.as_bytes());
            let blocks_to_advance = self.constant::<U64Variable>(2u64);
            let height = self.add(blocks_to_advance, next_block.header.inner_lite.height);
            bytes.extend_from_slice(&to_le_bytes::<_, _, D, 8>(self, &height).0);
            let bytes: [ByteVariable; 41] = bytes.try_into().unwrap();
            BytesVariable(bytes)
        }
    }
}

pub trait Verify<L: PlonkParameters<D>, const D: usize> {
    fn verify(&mut self, proof: ProofVariable) -> BoolVariable;
}

impl<L: PlonkParameters<D>, const D: usize> Verify<L, D> for CircuitBuilder<L, D> {
    fn verify(&mut self, proof: ProofVariable) -> BoolVariable {
        let block_hash = proof.block_header.hash(self);

        let block_hash_matches = self.is_equal(block_hash, proof.outcome_proof_block_hash);

        let outcome_matches = self.verify_outcome(
            &proof.block_header.inner_lite.outcome_root,
            &proof.outcome_proof,
            &proof.outcome_hash,
            &proof.outcome_root_proof,
        );

        let block_matches =
            self.verify_block(&proof.head_block_root, &proof.block_proof, &block_hash);

        let comp = self.and(block_matches, outcome_matches);
        let verified = self.and(comp, block_hash_matches);
        self.assertx(verified);
        verified
    }
}

// TODO: test this and reuse for block header inner
fn to_le_bytes<L: PlonkParameters<D>, V: CircuitVariable, const D: usize, const N: usize>(
    b: &mut CircuitBuilder<L, D>,
    v: &V,
) -> BytesVariable<N> {
    let mut bytes = vec![];
    for target in v.targets() {
        let mut bits = b.api.split_le(target, 32);
        bits.reverse();
        let to_extend = bits
            .chunks(8)
            .rev()
            .map(|chunk| {
                let targets = chunk.iter().map(|b| b.target).collect_vec();
                ByteVariable::from_targets(&targets)
            })
            .collect_vec();
        bytes.extend(to_extend);
    }
    BytesVariable(bytes.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use near_light_client_protocol::{Protocol, StakeInfo};

    use self::assert_eq;
    use super::*;
    use crate::{test_utils::*, variables::*};

    #[test]
    fn test_header_hash() {
        let header = to_header(test_first().body);
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
    fn test_ensure_stake() {
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
        let test_header = to_header(test_next().body);
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
        let (header, bps, _) = testnet_state();
        let bps_hash = CryptoHash::hash_borsh(bps.clone());

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
            let is_valid =
                builder.ensure_next_bps_is_valid(&header.inner_lite.next_bp_hash, &next_bps_hash);
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

            let mut bytes = vec![];
            for target in next_block.header.inner_lite.height.targets() {
                let mut bits = builder.api.split_le(target, 32);
                bits.reverse();
                let to_extend = bits
                    .chunks(8)
                    .rev()
                    .map(|chunk| {
                        let targets = chunk.iter().map(|b| b.target).collect_vec();
                        ByteVariable::from_targets(&targets)
                    })
                    .collect_vec();
                bytes.extend(to_extend);
            }
            builder.write::<BytesVariable<8>>(BytesVariable(bytes.try_into().unwrap()));
        };
        let writer = |input: &mut PI| {
            input.write::<BlockVariable>(next_block.clone().into());
        };
        let assertions = |mut output: PO| {
            let bytes = output.read::<BytesVariable<8>>();
            println!("{:?}", bytes);
            assert_eq!(bytes, next_block.inner_lite.height.to_le_bytes());
        };
        builder_suite(define, writer, assertions);
    }
}

/// These tests require either:
/// - A LOT of time if running in debug mode
/// - A LOT of RAM if running in release
///
/// TODO: CI for only beefy tests
#[cfg(test)]
mod beefy_tests {
    use serial_test::serial;

    use crate::{
        builder::{Ensure, Sync, Verify},
        test_utils::*,
        variables::*,
    };

    #[test]
    #[serial]
    #[ignore]
    fn beefy_builder_test_next_bps() {
        let (header, bps, _) = testnet_state();
        let bps_hash = CryptoHash::hash_borsh(bps.clone());

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
            let is_valid =
                builder.ensure_next_bps_is_valid(&header.inner_lite.next_bp_hash, &next_bps_hash);
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
    #[serial]
    #[ignore]
    fn beefy_builder_test_proof_blackbox() {
        let block_root =
            CryptoHash::from_str("WWrLWbWHwSmjtTn5oBZPYgRCuCYn6fkYVa4yhPWNK4L").unwrap();

        let define = |builder: &mut B| {
            let registered_proof = builder.read::<ProofVariable>();
            let proof_verified = builder.verify(registered_proof);
            builder.write::<BoolVariable>(proof_verified);
        };
        let writer = |input: &mut PI| {
            input.write::<ProofVariable>(
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
    #[serial]
    #[ignore]
    fn beefy_builder_test_sync_across_epoch_boundaries() {
        let (head, next_bps, next_block) = test_state();

        let define = |builder: &mut B| {
            let head = builder.read::<HeaderVariable>();
            let bps = builder.read::<BpsArr<ValidatorStakeVariable>>();
            let next_block = builder.read::<BlockVariable>();
            let synced = builder.sync(&head, &bps, &next_block);
            builder.write::<HeaderVariable>(synced);
        };
        let writer = |input: &mut PI| {
            input.write::<HeaderVariable>(head.into());
            input.write::<BpsArr<ValidatorStakeVariable>>(bps_to_variable(Some(next_bps)));
            input.write::<BlockVariable>(next_block.clone().into());
        };
        let assertions = |mut output: PO| {
            let header = output.read::<HeaderVariable>();
            println!("header: {:?}", header);
            // TODO: assert
        };
        builder_suite(define, writer, assertions);
    }

    #[test]
    #[serial]
    #[ignore]
    fn beefy_builder_test_bounded_signatures() {
        let (_, bps, next_block) = test_state();
        const BPS_AMT: usize = 15;

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

            builder.validate_signatures(&next_block_approvals, &bps, msg);
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
}

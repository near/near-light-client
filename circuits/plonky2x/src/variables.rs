use crate::merkle::determine_direction;
use ethers::types::U256;
use near_light_client_protocol::config::NUM_BLOCK_PRODUCER_SEATS;
use near_light_client_protocol::prelude::{Header, Itertools};
use near_light_client_protocol::{
    merkle_util::MerklePath, prelude::AccountId, prelude::CryptoHash, BlockHeaderInnerLiteView,
    LightClientBlockView, Signature, ValidatorStake,
};
use near_light_client_protocol::{Proof, StakeInfo, Synced};
use plonky2x::frontend::curta::ec::point::CompressedEdwardsY;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariable;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariableValue;
use plonky2x::frontend::hint::simple::hint::Hint;
use plonky2x::frontend::vars::EvmVariable;
use plonky2x::frontend::{curta::ec::point::CompressedEdwardsYVariable, uint::Uint};
use plonky2x::prelude::*;
use pretty_assertions::assert_eq;
use serde::{Deserialize, Serialize};

// TODO: remove any unused fields like account id etc?
// TODO: if we use borsh here be careful of order

/// TODO: check if BPS seats changes for testnet/mainnet
/// Type for omitting the size across the codebase for arrays that are the same size as BPS
pub(crate) type BpsArr<T, const A: usize = NUM_BLOCK_PRODUCER_SEATS> = ArrayVariable<T, A>;

pub type CryptoHashVariable = Bytes32Variable;
pub type BlockHeightVariable = U64Variable;
pub type BalanceVariable = U128Variable;
pub type AccountIdVariable = BytesVariable<{ AccountId::MAX_LEN }>; // TODO: decide if this is a
                                                                    // reasonable way

// TODO: add handling of empty path elements
#[derive(CircuitVariable, Clone, Debug)]
pub struct MerklePathVariable<const A: usize> {
    pub path: ArrayVariable<Bytes32Variable, A>,
    pub indices: ArrayVariable<BoolVariable, A>,
}
impl<F: RichField, const A: usize> From<MerklePath> for MerklePathVariableValue<A, F> {
    fn from(path: MerklePath) -> Self {
        assert!(path.len() <= A);

        let mut indices = path
            .iter()
            .map(|x| &x.direction)
            .map(determine_direction)
            .collect_vec();
        // FIXME: Hmm, this seems problematic potentially since it might hash the wrong way
        // verify.
        indices.resize(A, Default::default());

        let mut path = path.iter().map(|x| x.hash.0.into()).collect_vec();
        path.resize(A, Default::default());

        Self { path, indices }
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct HeaderVariable {
    pub prev_block_hash: CryptoHashVariable,
    pub inner_rest_hash: CryptoHashVariable,
    pub inner_lite: HeaderInnerVariable,
}
impl<F: RichField> From<Header> for HeaderVariableValue<F> {
    fn from(header: Header) -> Self {
        Self {
            prev_block_hash: header.prev_block_hash.0.into(),
            inner_rest_hash: header.inner_rest_hash.0.into(),
            inner_lite: header.inner_lite.into(),
        }
    }
}
impl<F: RichField> From<LightClientBlockView> for HeaderVariableValue<F> {
    fn from(header: LightClientBlockView) -> Self {
        Self {
            prev_block_hash: header.prev_block_hash.0.into(),
            inner_rest_hash: header.inner_rest_hash.0.into(),
            inner_lite: header.inner_lite.into(),
        }
    }
}
impl HeaderVariable {
    pub(crate) fn hash<L: PlonkParameters<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<L, D>,
    ) -> CryptoHashVariable {
        let inner_lite = self.inner_lite.hash(b);
        let lite_rest = b.curta_sha256_pair(inner_lite, self.inner_rest_hash);
        let hash = b.curta_sha256_pair(lite_rest, self.prev_block_hash);
        hash
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct HeaderInnerVariable {
    pub height: U64Variable,
    pub epoch_id: CryptoHashVariable,
    pub next_epoch_id: CryptoHashVariable,
    pub prev_state_root: CryptoHashVariable,
    pub outcome_root: CryptoHashVariable,
    pub timestamp: U64Variable,
    pub next_bp_hash: CryptoHashVariable,
    pub block_merkle_root: CryptoHashVariable,
}
impl<F: RichField> From<BlockHeaderInnerLiteView> for HeaderInnerVariableValue<F> {
    fn from(header: BlockHeaderInnerLiteView) -> Self {
        Self {
            height: header.height.into(),
            epoch_id: header.epoch_id.0.into(),
            next_epoch_id: header.next_epoch_id.0.into(),
            prev_state_root: header.prev_state_root.0.into(),
            outcome_root: header.outcome_root.0.into(),
            timestamp: if header.timestamp > 0 {
                header.timestamp
            } else {
                header.timestamp_nanosec
            }
            .into(),
            next_bp_hash: header.next_bp_hash.0.into(),
            block_merkle_root: header.block_merkle_root.0.into(),
        }
    }
}
pub const INNER_ENCODED_LEN: usize = 208;

impl HeaderInnerVariable {
    pub(crate) fn encode<L: PlonkParameters<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<L, D>,
    ) -> BytesVariable<INNER_ENCODED_LEN> {
        // TODO: doubt we can abi encode this
        let mut input_stream = VariableStream::new();
        input_stream.write(&self.height);
        input_stream.write(&self.epoch_id);
        input_stream.write(&self.next_epoch_id);
        input_stream.write(&self.prev_state_root);
        input_stream.write(&self.outcome_root);
        input_stream.write(&self.timestamp);
        input_stream.write(&self.next_bp_hash);
        input_stream.write(&self.block_merkle_root);

        let output_bytes = b.hint(input_stream, EncodeInner);
        let bytes = output_bytes.read::<BytesVariable<208>>(b);
        bytes
    }
    pub(crate) fn hash<L: PlonkParameters<D>, const D: usize>(
        &self,
        b: &mut CircuitBuilder<L, D>,
    ) -> CryptoHashVariable {
        let bytes = self.encode(b);
        b.curta_sha256(&bytes.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodeInner;
impl<L: PlonkParameters<D>, const D: usize> Hint<L, D> for EncodeInner {
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let mut bytes: Vec<u8> = vec![];
        let height = input_stream.read_value::<U64Variable>();
        let epoch_id = input_stream.read_value::<CryptoHashVariable>();
        let next_epoch_id = input_stream.read_value::<CryptoHashVariable>();
        let prev_state_root = input_stream.read_value::<CryptoHashVariable>();
        let outcome_root = input_stream.read_value::<CryptoHashVariable>();
        let timestamp = input_stream.read_value::<U64Variable>();
        let next_bp_hash = input_stream.read_value::<CryptoHashVariable>();
        let block_merkle_root = input_stream.read_value::<CryptoHashVariable>();

        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&epoch_id.0);
        bytes.extend_from_slice(&next_epoch_id.0);
        bytes.extend_from_slice(&prev_state_root.0);
        bytes.extend_from_slice(&outcome_root.0);
        bytes.extend_from_slice(&timestamp.to_le_bytes());
        bytes.extend_from_slice(&next_bp_hash.0);
        bytes.extend_from_slice(&block_merkle_root.0);

        assert_eq!(
            bytes.len(),
            INNER_ENCODED_LEN,
            "expected {} bytes, got {}",
            INNER_ENCODED_LEN,
            bytes.len()
        );

        let bytes: [u8; INNER_ENCODED_LEN] = bytes.try_into().unwrap();
        output_stream.write_value::<BytesVariable<INNER_ENCODED_LEN>>(bytes);
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct BlockVariable {
    pub header: HeaderVariable,
    pub next_block_inner_hash: CryptoHashVariable,
    pub next_bps: BpsArr<ValidatorStakeVariable>,
    pub approvals_after_next: BpsApprovals<NUM_BLOCK_PRODUCER_SEATS>,
    pub next_bp_hash: CryptoHashVariable,
}

impl<F: RichField> From<LightClientBlockView> for BlockVariableValue<F> {
    fn from(block: LightClientBlockView) -> Self {
        let next_bp_hash = block
            .next_bps
            .as_ref()
            .map(|bps| CryptoHash::hash_borsh(bps))
            .unwrap_or_default()
            .0
            .into();

        Self {
            next_block_inner_hash: block.next_block_inner_hash.0.into(),
            header: block.clone().into(),
            next_bps: bps_to_variable(block.next_bps),
            approvals_after_next: block.approvals_after_next.into(),
            next_bp_hash,
        }
    }
}

pub(crate) fn bps_to_variable<F: RichField, T: Into<ValidatorStake>>(
    next_bps: Option<Vec<T>>,
) -> Vec<ValidatorStakeVariableValue<F>> {
    next_bps
        .map(|next_bps| {
            let mut bps = next_bps
                .into_iter()
                .take(NUM_BLOCK_PRODUCER_SEATS)
                .map(Into::<ValidatorStake>::into)
                .map(Into::<ValidatorStakeVariableValue<F>>::into)
                .collect_vec();
            bps.resize(NUM_BLOCK_PRODUCER_SEATS, Default::default());
            bps
        })
        .unwrap_or_else(|| vec![Default::default(); NUM_BLOCK_PRODUCER_SEATS])
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct BpsApprovals<const AMT: usize> {
    pub is_active: BpsArr<BoolVariable, AMT>,
    pub signatures: BpsArr<EDDSASignatureVariable, AMT>,
}

impl<F: RichField, const AMT: usize> From<Vec<Option<Box<Signature>>>>
    for BpsApprovalsValue<AMT, F>
{
    fn from(approvals: Vec<Option<Box<Signature>>>) -> Self {
        let mut is_active = vec![false; AMT];
        let mut signatures = vec![Default::default(); AMT];

        approvals
            .into_iter()
            .take(AMT)
            .enumerate()
            .for_each(|(i, s)| {
                is_active[i] = s.is_some();
                let s: SignatureVariableValue<F> = s.into();
                signatures[i] = s;
            });

        Self {
            is_active: is_active.into(),
            signatures: signatures
                .into_iter()
                .map(|x| x.signature)
                .collect_vec()
                .into(),
        }
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct ValidatorStakeVariable {
    pub account_id: AccountIdVariable,
    pub public_key: PublicKeyVariable,
    pub stake: BalanceVariable,
}

impl<F: RichField> From<ValidatorStake> for ValidatorStakeVariableValue<F> {
    fn from(vs: ValidatorStake) -> Self {
        let public_key = CompressedEdwardsY(vs.public_key().unwrap_as_ed25519().0);
        let stake = vs.stake();
        let mut account_id = vs.take_account_id().as_str().as_bytes().to_vec();
        account_id.resize(AccountId::MAX_LEN, 0);
        Self {
            account_id: account_id.try_into().unwrap(), // SAFETY: already checked this above
            public_key: public_key.into(),
            stake: stake.into(),
        }
    }
}

impl<F: RichField> Default for ValidatorStakeVariableValue<F> {
    fn default() -> Self {
        let bytes: [u8; AccountId::MAX_LEN] = [0u8; AccountId::MAX_LEN];
        let pk = CompressedEdwardsY::default();
        let stake = 0_u128;

        Self {
            account_id: bytes.into(),
            public_key: pk.into(),
            stake: stake.into(),
        }
    }
}

pub type PublicKeyVariable = CompressedEdwardsYVariable;
pub type PublicKeyVariableValue = CompressedEdwardsY;

#[derive(CircuitVariable, Clone, Debug)]
pub struct SignatureVariable {
    pub signature: EDDSASignatureVariable,
}

impl<F: RichField> From<Option<Box<Signature>>> for SignatureVariableValue<F> {
    fn from(sig: Option<Box<Signature>>) -> Self {
        sig.and_then(|s| match *s {
            Signature::ED25519(s) => Some(Self {
                signature: EDDSASignatureVariableValue {
                    r: CompressedEdwardsY(*s.r_bytes()),
                    s: U256::from_little_endian(s.s_bytes()),
                },
            }),
            // Silently ignores invalid signatures (ECDSA)
            // The reasoning being that ECDSA is being phased out and almost all validators
            // use EDDSA.
            // If we still need this, we should implement ECDSA.
            _ => None,
        })
        .unwrap_or_default()
    }
}

impl<F: RichField> Default for SignatureVariableValue<F> {
    fn default() -> Self {
        Self {
            signature: EDDSASignatureVariableValue {
                r: CompressedEdwardsY::default(),
                s: Default::default(),
            },
        }
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct ProofVariable<const OPD: usize, const ORPD: usize, const BPD: usize> {
    pub head_block_root: CryptoHashVariable,
    // TODO: constrain the outcome hash by borsh encoding in the circuit, not here
    pub outcome_hash: CryptoHashVariable,
    pub outcome_proof_block_hash: CryptoHashVariable,
    pub outcome_proof: MerklePathVariable<OPD>, // TODO: get real number here
    pub outcome_root_proof: MerklePathVariable<ORPD>, // TODO: get real number here
    pub block_header: HeaderVariable,
    pub block_proof: MerklePathVariable<BPD>, // TODO: get real number here
}

impl<F, const OPD: usize, const ORPD: usize, const BPD: usize> From<Proof>
    for ProofVariableValue<OPD, ORPD, BPD, F>
where
    F: RichField,
{
    fn from(proof: Proof) -> Self {
        match proof {
            Proof::Basic {
                head_block_root,
                proof,
            } => Self {
                head_block_root: head_block_root.0.into(),
                outcome_hash: CryptoHash::hash_borsh(proof.outcome_proof.to_hashes())
                    .0
                    .into(),
                outcome_proof_block_hash: proof.outcome_proof.block_hash.0.into(),
                outcome_proof: proof.outcome_proof.proof.into(),
                outcome_root_proof: proof.outcome_root_proof.into(),
                block_header: proof.block_header_lite.into(),
                block_proof: proof.block_proof.into(),
            },
            Proof::Experimental(_) => todo!("Batch proving"),
        }
    }
}

// TODO: likely these don't need to be constrained in the circuit so wont need to
// implement circuit variable for these, we blind these in the batch proofs anyway
// pub struct ExecutionOutcomeWithId {
//     pub proof: MerklePath<32>,
//     pub block_hash: CryptoHash,
//     pub id: CryptoHash,
//     pub outcome: ExecutionOutcome,
// }
//
// pub pub struct ExecutionOutcome {
//     pub logs: Vec<String>,
//     pub receipt_ids: Vec<CryptoHash>,
//     pub gas_burnt: U64Variable,
//     pub tokens_burnt: Balance,
//     pub executor_id: AccountId,
//     pub status: ExecutionStatusView,
//     pub metadata: ExecutionMetadataView,
// }

#[derive(CircuitVariable, Clone, Debug)]
pub struct StakeInfoVariable {
    pub approved: BalanceVariable,
    pub total: BalanceVariable,
}

impl<F: RichField> From<StakeInfo> for StakeInfoVariableValue<F> {
    fn from(value: StakeInfo) -> Self {
        Self {
            approved: value.approved.into(),
            total: value.total.into(),
        }
    }
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct HeaderHash<const N: usize>;
//
// impl<L: PlonkParameters<D>, const D: usize, const N: usize> Hint<L, D> for HeaderHash<N> {
//     fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
//         let inner_lite_hash = input_stream.read_value::<CryptoHash>();
//         let inner_rest_hash = input_stream.read_value::<CryptoHash>();
//         let prev_block_hash = input_stream.read_value::<CryptoHash>();
//
//         let next_block_hash = sh;
//         output_stream.write_value::<CryptoHash>(next_block_hash);
//     }
// }

pub type ApprovalMessage = BytesVariable<41>;
// TODO: not sure these even need to be hints
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildEndorsement;

impl<L: PlonkParameters<D>, const D: usize> Hint<L, D> for BuildEndorsement {
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let mut bytes = vec![];
        let next_block_hash = input_stream.read_value::<CryptoHashVariable>();
        let next_block_height = input_stream.read_value::<U64Variable>();

        bytes.push(0u8);
        bytes.extend_from_slice(&next_block_hash.as_bytes());
        bytes.extend_from_slice(&(next_block_height + 2).to_le_bytes());

        output_stream.write_value::<ApprovalMessage>(bytes.try_into().unwrap());
    }
}
// impl<const N: usize> BuildEndorsement<N> {
//     pub fn build(
//         &self,
//         builder: &mut CircuitBuilder<Fr, D>,
//         next_block_hash: CryptoHash,
//         next_block_height: U64Variable,
//     ) -> BytesVariable<N> {
//         let mut input_stream = VariableStream::new();
//         input_stream.write(&next_block_hash);
//         input_stream.write(&next_block_height);
//
//         let mut output_stream = VariableStream::new();
//         let hint = BuildEndorsement::<N>;
//         let output_stream = hint.hint(&mut input_stream, &mut output_stream);
//         let next_header = output_stream.read::<Bytes32Variable>(self);
//         Self
//     }
// }

#[derive(CircuitVariable, Clone, Debug)]
pub struct SyncedVariable {
    pub new_head: HeaderVariable,
    pub next_bps_epoch: CryptoHashVariable,
    pub next_bps: BpsArr<ValidatorStakeVariable>,
}

impl<F> From<Synced> for SyncedVariableValue<F>
where
    F: RichField,
{
    fn from(value: Synced) -> Self {
        let default_bps = vec![ValidatorStakeVariableValue::default(); NUM_BLOCK_PRODUCER_SEATS];
        Self {
            new_head: value.new_head.into(),
            next_bps_epoch: value
                .next_bps
                .as_ref()
                .map(|v| v.0 .0 .0.into())
                .unwrap_or_default(),
            next_bps: value
                .next_bps
                .map(|v| v.1.into_iter().map(Into::into).collect_vec())
                .unwrap_or(default_bps),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests() {
        todo!()
    }
}

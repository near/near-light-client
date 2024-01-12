use ethers::types::{H256, U256};
use near_light_client_protocol::prelude::Header;
use near_light_client_protocol::{
    merkle_util::MerklePath, prelude::AccountId, prelude::CryptoHash, BlockHeaderInnerLiteView,
    LightClientBlockView, Signature, ValidatorStake,
};
use plonky2x::frontend::curta::ec::point::CompressedEdwardsY;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::{
    EDDSASignatureVariable, DUMMY_SIGNATURE,
};
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::{
    EDDSASignatureVariableValue, DUMMY_PUBLIC_KEY,
};
use plonky2x::frontend::hint::simple::hint::Hint;
use plonky2x::frontend::{curta::ec::point::CompressedEdwardsYVariable, uint::Uint};
use plonky2x::prelude::*;
use serde::{Deserialize, Serialize};

// TODO: if we use borsh here be careful of order
// TODO: borsh? would need encoding for messages, make a hint
//
// TODO: optional variable
// TODO: get constrained numbers
//
// EVM write synced
// EVM write proof

pub const MAX_ACCOUNT_ID_LEN: usize = 32; // TODO: get real number here
pub const MAX_EPOCH_VALIDATORS: usize = 100; // TODO: real number

pub type CryptoHashVariable = Bytes32Variable;
pub type BlockHeightVariable = U64Variable;
pub type BalanceVariable = U128Variable;
pub type AccountIdVariable = BytesVariable<{ AccountId::MAX_LEN }>;

#[derive(CircuitVariable, Clone, Debug)]
pub struct MerklePathVariable<const M: usize> {
    pub path: ArrayVariable<Bytes32Variable, M>,
    pub indices: ArrayVariable<BoolVariable, M>,
}

impl<F: RichField, const M: usize> From<MerklePath> for MerklePathVariableValue<M, F> {
    fn from(value: MerklePath) -> Self {
        assert_eq!(value.len(), M, "Merkle path must be of length M");
        let indices: Vec<bool> = value
            .iter()
            .map(|x| match x.direction {
                near_light_client_protocol::Direction::Left => true,
                near_light_client_protocol::Direction::Right => false,
            })
            .collect();
        Self {
            path: value.iter().map(|x| x.hash.0.into()).collect::<Vec<_>>(),
            indices,
        }
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

// TODO: test this individually as i think they arent borsh encoded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerLiteHash<const N: usize>;
impl<L: PlonkParameters<D>, const D: usize, const N: usize> Hint<L, D> for InnerLiteHash<N> {
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

        assert_eq!(bytes.len(), N, "expected {} bytes, got {}", N, bytes.len());

        let bytes: [u8; N] = bytes.try_into().unwrap();
        output_stream.write_value::<BytesVariable<N>>(bytes);
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct BlockVariable {
    pub prev_block_hash: CryptoHashVariable,
    pub next_block_inner_hash: CryptoHashVariable,
    pub inner_lite: HeaderInnerVariable,
    pub inner_rest_hash: CryptoHashVariable,
    // TODO: sparse arrays for this and approvals
    pub next_bps: ArrayVariable<ValidatorStakeVariable, MAX_EPOCH_VALIDATORS>,
    pub approvals_after_next: BpsApprovals,
}

impl<F: RichField> From<LightClientBlockView> for BlockVariableValue<F> {
    fn from(block: LightClientBlockView) -> Self {
        assert_eq!(block.next_bps.as_ref().unwrap().len(), MAX_EPOCH_VALIDATORS);
        Self {
            prev_block_hash: block.prev_block_hash.0.into(),
            next_block_inner_hash: block.next_block_inner_hash.0.into(),
            inner_lite: block.inner_lite.into(),
            inner_rest_hash: block.inner_rest_hash.0.into(),
            next_bps: if let Some(next_bps) = block.next_bps {
                next_bps
                    .into_iter()
                    .map(|s| {
                        let s: ValidatorStake = s.into();
                        s
                    })
                    .map(Into::into)
                    .collect()
            } else {
                // FIXME: needs to fill to spsace
                vec![]
            }
            .into(),
            approvals_after_next: block.approvals_after_next.into(),
        }
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct BpsApprovals {
    pub is_active: ArrayVariable<BoolVariable, MAX_EPOCH_VALIDATORS>,
    pub signatures: ArrayVariable<EDDSASignatureVariable, MAX_EPOCH_VALIDATORS>,
}

impl<F: RichField> From<Vec<Option<Box<Signature>>>> for BpsApprovalsValue<F> {
    fn from(approvals: Vec<Option<Box<Signature>>>) -> Self {
        let mut is_active = vec![];
        let signatures = approvals
            .into_iter()
            .map(|sig| {
                is_active.push(sig.is_some());
                let sig: SignatureVariableValue<F> = sig.into();
                sig.ed25519
            })
            .collect::<Vec<EDDSASignatureVariableValue<F>>>();

        assert_eq!(is_active.len(), MAX_EPOCH_VALIDATORS);
        assert_eq!(signatures.len(), MAX_EPOCH_VALIDATORS);

        Self {
            is_active: is_active.into(),
            signatures: signatures.into(),
        }
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct ValidatorStakeVariable {
    /// Account that stakes money.
    pub account_id: AccountIdVariable,
    /// Public key of the proposed validator.
    pub public_key: PublicKeyVariable,
    /// Stake / weight of the validator.
    pub stake: BalanceVariable,
}

impl<F: RichField> From<ValidatorStake> for ValidatorStakeVariableValue<F> {
    fn from(stake: ValidatorStake) -> Self {
        let pk = stake.public_key().key_data();
        let y = CompressedEdwardsY::from_slice(&pk).expect("CompressedEdwardsY::from_slice");
        // TODO: fixme
        let mut id_bytes = borsh::to_vec(stake.account_id()).unwrap();
        id_bytes.resize(AccountId::MAX_LEN, 0);
        Self {
            account_id: id_bytes.try_into().unwrap(),
            public_key: y.into(),
            stake: stake.stake().into(),
        }
    }
}

// TODO: k256 ECDSA and manual enum impl for signatures and public keys
// #[derive( Clone, Debug)]
// enum PublicKey {
//     Ed25519(CompressedEdwardsYVariable),
// }
pub type PublicKeyVariable = CompressedEdwardsYVariable;
pub type PublicKeyVariableValue = CompressedEdwardsY;

#[derive(CircuitVariable, Clone, Debug)]
pub struct SignatureVariable {
    pub ed25519: EDDSASignatureVariable,
    //TODO: pub ecdsa: Option<ECDSASignatureVariable>
}

impl<F: RichField> From<Option<Box<Signature>>> for SignatureVariableValue<F> {
    fn from(sig: Option<Box<Signature>>) -> Self {
        let (r, s) = sig
            .map(|s| match *s {
                Signature::ED25519(s) => (*s.r_bytes(), *s.s_bytes()),
                Signature::SECP256K1(_) => {
                    panic!("ECDSA is being phased out and validators don't use it")
                }
            })
            .unwrap_or_else(|| {
                (
                    DUMMY_SIGNATURE[0..32].try_into().unwrap(),
                    DUMMY_SIGNATURE[32..64].try_into().unwrap(),
                )
            });
        let sig = EDDSASignatureVariableValue {
            r: CompressedEdwardsY(r),
            s: U256::from_little_endian(&s),
        };
        Self {
            ed25519: sig.into(),
        }
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct ProofVariable<const OPD: usize, const ORPD: usize, const BPD: usize> {
    pub head_block_root: CryptoHashVariable,
    // TODO: make variable pub outcome_proof: ExecutionOutcomeWithId,
    pub outcome_hash: CryptoHashVariable,
    pub outcome_proof_block_hash: CryptoHashVariable,
    pub outcome_proof: MerklePathVariable<OPD>, // TODO: get real number here
    pub outcome_root_proof: MerklePathVariable<ORPD>, // TODO: get real number here
    pub block_header: HeaderVariable,
    pub block_proof: MerklePathVariable<BPD>, // TODO: get real number here
}

impl<F, const OPD: usize, const ORPD: usize, const BPD: usize>
    From<near_light_client_protocol::Proof> for ProofVariableValue<OPD, ORPD, BPD, F>
where
    F: RichField,
{
    fn from(proof: near_light_client_protocol::Proof) -> Self {
        match proof {
            near_light_client_protocol::Proof::Basic {
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
            near_light_client_protocol::Proof::Experimental(_) => todo!("Batch proving"),
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

impl<F: RichField> From<near_light_client_protocol::StakeInfo> for StakeInfoVariableValue<F> {
    fn from(value: near_light_client_protocol::StakeInfo) -> Self {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildEndorsement<const N: usize>;

impl<L: PlonkParameters<D>, const D: usize, const N: usize> Hint<L, D> for BuildEndorsement<N> {
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let mut bytes = vec![];
        let next_block_hash = input_stream.read_value::<CryptoHashVariable>();
        let next_block_height = input_stream.read_value::<U64Variable>();

        bytes.push(0u8);
        bytes.extend_from_slice(&next_block_hash.as_bytes());
        bytes.extend_from_slice(&next_block_height.to_le_bytes());

        assert_eq!(bytes.len(), N, "expected {} bytes, got {}", N, bytes.len());
        output_stream.write_value::<BytesVariable<N>>(bytes.try_into().unwrap());
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

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2x::frontend::vars::EvmVariable;

    #[test]
    fn test_encodepacked() {
        let mut builder = DefaultBuilder::new();
        let mut pw = PartialWitness::new();
        let x1 = 10;
        let x = builder.init::<U64Variable>();

        x.set(&mut pw, x1);

        assert_eq!(x.get(&pw), x1);

        println!("x1: {:?}", x1.to_le_bytes());
        println!("x: {:?}", x.encode(&mut builder));

        let circuit = builder.build();
        let proof = circuit.data.prove(pw).unwrap();
        circuit.data.verify(proof).unwrap();
    }
}

use crate::codec::{self, Borsh};
use borsh::BorshSerialize;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariable;
use plonky2x::frontend::hint::simple::hint::Hint;
use plonky2x::frontend::{curta::ec::point::CompressedEdwardsYVariable, uint::Uint};
use plonky2x::prelude::*;
use plonky2x::utils::hash::sha256;
use serde::{Deserialize, Serialize};

// TODO: if we use borsh here be careful of order
// TODO: ideally just use into conversions and expose protocol via types crate
// TODO: borsh? would need encoding for messages, make a hint
// TODO: optional variable
// TODO: sparse arrays for BPS, check tendermint, or we make own pub type entirely
// TODO: ecdsa sigs & keys
// TODO: get constrained numbers
//
// EVM write synced
// EVM write proof

pub const MAX_ACCOUNT_ID_LEN: usize = 32; // TODO: get real number here
pub const MAX_EPOCH_VALIDATORS: usize = 128; // TODO: real number

pub type CryptoHash = Bytes32Variable;
pub type BlockHeight = U64Variable;
pub type Balance = U64Variable;
pub type AccountId = BytesVariable<MAX_ACCOUNT_ID_LEN>; // TODO: likely an issue, implement the var here, or just use a u64,
                                                        // TODO: get depths of all proofs

// TODO: maybe find a nicer way to do this
#[derive(CircuitVariable, Clone, Debug)]
pub struct EpochBlockProducers {
    pub active: ArrayVariable<BoolVariable, MAX_EPOCH_VALIDATORS>,
    pub bps: ArrayVariable<ValidatorStake, MAX_EPOCH_VALIDATORS>,
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct MerklePath<const M: usize> {
    pub path: ArrayVariable<Bytes32Variable, M>,
    pub indices: ArrayVariable<BoolVariable, M>,
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct Header {
    pub prev_block_hash: CryptoHash,
    pub inner_rest_hash: Bytes32Variable,
    pub inner_lite: HeaderInner,
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct HeaderInner {
    pub height: U64Variable,
    pub epoch_id: CryptoHash,
    pub next_epoch_id: CryptoHash,
    pub prev_state_root: CryptoHash,
    pub outcome_root: CryptoHash,
    /// Legacy json number. Should not be used. TODO: delete
    pub timestamp: U64Variable,
    pub timestamp_nanosec: U64Variable,
    pub next_bp_hash: CryptoHash,
    pub block_merkle_root: CryptoHash,
}

// TODO: test this individually as i think they arent borsh encoded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerLiteHash<const N: usize>;
impl<L: PlonkParameters<D>, const D: usize, const N: usize> Hint<L, D> for InnerLiteHash<N> {
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let mut bytes: Vec<u8> = vec![];
        let height = input_stream.read_value::<U64Variable>();
        let epoch_id = input_stream.read_value::<CryptoHash>();
        let next_epoch_id = input_stream.read_value::<CryptoHash>();
        let prev_state_root = input_stream.read_value::<CryptoHash>();
        let outcome_root = input_stream.read_value::<CryptoHash>();
        let timestamp = input_stream.read_value::<U64Variable>();
        let timestamp_nanosec = input_stream.read_value::<U64Variable>();
        let next_bp_hash = input_stream.read_value::<CryptoHash>();
        let block_merkle_root = input_stream.read_value::<CryptoHash>();

        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&epoch_id.0);
        bytes.extend_from_slice(&next_epoch_id.0);
        bytes.extend_from_slice(&prev_state_root.0);
        bytes.extend_from_slice(&outcome_root.0);
        bytes.extend_from_slice(&timestamp.to_le_bytes());
        bytes.extend_from_slice(&timestamp_nanosec.to_le_bytes());
        bytes.extend_from_slice(&next_bp_hash.0);
        bytes.extend_from_slice(&block_merkle_root.0);


        let hash = sha256(&bytes);
        output_stream.write_value::<Bytes32Variable>(hash.into());
    }
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct Block {
    pub prev_block_hash: CryptoHash,
    pub next_block_inner_hash: CryptoHash,
    pub inner_lite: HeaderInner,
    pub inner_rest_hash: CryptoHash,
    // TODO: sparse arrays for this and approvals
    pub next_bps: EpochBlockProducers,
    pub approvals_after_next: ArrayVariable<Signature, MAX_EPOCH_VALIDATORS>,
}

#[derive(CircuitVariable, Clone, Debug)]
pub struct ValidatorStake {
    /// Account that stakes money.
    pub account_id: AccountId,
    /// Public key of the proposed validator.
    pub public_key: PublicKey,
    /// Stake / weight of the validator.
    pub stake: Balance,
}

// TODO: k256 ECDSA and manual enum impl for signatures and public keys
// #[derive( Clone, Debug)]
// enum PublicKey {
//     Ed25519(CompressedEdwardsYVariable),
// }
pub type PublicKey = CompressedEdwardsYVariable;
pub type Signature = EDDSASignatureVariable;

#[derive(CircuitVariable, Clone, Debug)]
pub struct Proof {
    pub head_block_root: CryptoHash,
    // TODO: make variable pub outcome_proof: ExecutionOutcomeWithId,
    pub outcome_hash: CryptoHash,
    pub outcome_proof_block_hash: CryptoHash,
    pub outcome_proof: MerklePath<32>, // TODO: get real number here
    pub outcome_root_proof: MerklePath<32>, // TODO: get real number here
    pub block_header: Header,
    pub block_proof: MerklePath<256>, // TODO: get real number here
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
pub struct StakeInfo {
    pub approved_stake: Balance,
    pub total_stake: Balance,
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
        let next_block_hash = input_stream.read_value::<CryptoHash>();
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

use near_light_client_protocol::{merkle_util::MerklePath, prelude::Itertools};
use plonky2x::prelude::*;

/// This is an unprefixed merkle tree without collision resistance, this should
/// probably adapt the tendermint tree or introduce this functionality to
/// succinct's simple tree
pub trait NearMerkleTree {
    fn get_root_from_merkle_proof_hashed_leaf_unindex<const PROOF_DEPTH: usize>(
        &mut self,
        proof: &ArrayVariable<Bytes32Variable, PROOF_DEPTH>,
        path_indices: &ArrayVariable<BoolVariable, PROOF_DEPTH>,
        leaf: Bytes32Variable,
    ) -> Bytes32Variable;
    fn inner_hash(&mut self, left: &Bytes32Variable, right: &Bytes32Variable) -> Bytes32Variable;
}

impl<L: PlonkParameters<D>, const D: usize> NearMerkleTree for CircuitBuilder<L, D> {
    fn get_root_from_merkle_proof_hashed_leaf_unindex<const PROOF_DEPTH: usize>(
        &mut self,
        proof: &ArrayVariable<Bytes32Variable, PROOF_DEPTH>,
        path_indices: &ArrayVariable<BoolVariable, PROOF_DEPTH>,
        leaf: Bytes32Variable,
    ) -> Bytes32Variable {
        let mut hash_so_far = leaf;

        let default = self.constant::<Bytes32Variable>(INACTIVE_NODE.into());

        for i in 0..PROOF_DEPTH {
            let aunt = proof[i];
            let path_index = path_indices[i];

            let left_hash_pair = self.inner_hash(&hash_so_far, &aunt);
            let right_hash_pair = self.inner_hash(&aunt, &hash_so_far);

            let aunt_is_default = self.is_equal(aunt, default);

            let hash = self.select(path_index, right_hash_pair, left_hash_pair);

            hash_so_far = self.select(aunt_is_default, hash_so_far, hash)
        }
        hash_so_far
    }
    fn inner_hash(&mut self, left: &Bytes32Variable, right: &Bytes32Variable) -> Bytes32Variable {
        let mut encoded_leaf = vec![];

        encoded_leaf.extend(left.as_bytes().to_vec());
        encoded_leaf.extend(right.as_bytes().to_vec());

        self.curta_sha256(&encoded_leaf)
    }
}

pub fn determine_direction(dir: &near_light_client_protocol::Direction) -> bool {
    match dir {
        near_light_client_protocol::Direction::Left => true,
        near_light_client_protocol::Direction::Right => false,
    }
}

const INACTIVE_NODE: [u8; 32] = [255; 32];

#[derive(CircuitVariable, Clone, Debug)]
pub struct MerklePathVariable<const MAX_LEN: usize> {
    pub path: ArrayVariable<Bytes32Variable, MAX_LEN>,
    pub indices: ArrayVariable<BoolVariable, MAX_LEN>,
}
impl<F: RichField, const MAX_LEN: usize> From<MerklePath> for MerklePathVariableValue<MAX_LEN, F> {
    fn from(path: MerklePath) -> Self {
        assert!(path.len() <= MAX_LEN, "merkle path too long");

        let mut indices = path
            .iter()
            .map(|x| &x.direction)
            .map(determine_direction)
            .collect_vec();

        indices.resize(MAX_LEN, Default::default());

        let mut path = path.iter().map(|x| x.hash.0.into()).collect_vec();
        path.resize(MAX_LEN, INACTIVE_NODE.into());

        Self { path, indices }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::*, variables::ProofVariable};

    #[test]
    #[ignore]
    fn beefy_test_path_is_ignored_if_default() {
        let block_root =
            CryptoHash::from_str("WWrLWbWHwSmjtTn5oBZPYgRCuCYn6fkYVa4yhPWNK4L").unwrap();

        let define = |b: &mut B| {
            let p = b.read::<ProofVariable>();
            let hash = p.block_header.hash(b);

            let root = b.get_root_from_merkle_proof_hashed_leaf_unindex(
                &p.block_proof.path,
                &p.block_proof.indices,
                hash,
            );
            let v = b.is_equal(root, p.head_block_root);

            b.write::<BoolVariable>(v);
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
            assert!(output.read::<BoolVariable>());
        };
        builder_suite(define, writer, assertions);
    }
}

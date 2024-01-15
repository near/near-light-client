use plonky2x::prelude::*;

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

        for i in 0..PROOF_DEPTH {
            let aunt = proof[i];
            let path_index = path_indices[i];
            let left_hash_pair = self.inner_hash(&hash_so_far, &aunt);
            let right_hash_pair = self.inner_hash(&aunt, &hash_so_far);

            hash_so_far = self.select(path_index, right_hash_pair, left_hash_pair)
        }
        hash_so_far
    }
    fn inner_hash(&mut self, left: &Bytes32Variable, right: &Bytes32Variable) -> Bytes32Variable {
        let mut encoded_leaf = vec![];

        // Append the left bytes to the one byte.
        encoded_leaf.extend(left.as_bytes().to_vec());

        // Append the right bytes to the bytes so far.
        encoded_leaf.extend(right.as_bytes().to_vec());

        // Load the output of the hash.
        self.curta_sha256(&encoded_leaf)
    }
}

pub fn determine_direction(dir: &near_light_client_protocol::Direction) -> bool {
    match dir {
        near_light_client_protocol::Direction::Left => true,
        near_light_client_protocol::Direction::Right => false,
    }
}

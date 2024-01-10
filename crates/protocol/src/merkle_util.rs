use crate::prelude::*;
pub use near_primitives::merkle::combine_hash;
pub use near_primitives::merkle::MerklePath;
pub use near_primitives::merkle::{Direction, MerklePathItem};
use near_primitives_core::types::MerkleHash;

pub fn verify_hash<'a>(
    root: MerkleHash,
    path: impl Iterator<Item = &'a MerklePathItem>,
    item_hash: MerkleHash,
) -> bool {
    compute_root_from_path(path, item_hash) == root
}

pub fn compute_root_from_path<'a>(
    path: impl Iterator<Item = &'a MerklePathItem>,
    item_hash: MerkleHash,
) -> MerkleHash {
    let mut hash_so_far = item_hash;
    for uncle in path {
        match uncle.direction {
            Direction::Left => {
                hash_so_far = combine_hash(&uncle.hash, &hash_so_far);
            }
            Direction::Right => {
                hash_so_far = combine_hash(&hash_so_far, &uncle.hash);
            }
        }
    }
    hash_so_far
}

pub fn compute_root_from_path_and_item<'a, T: BorshSerialize>(
    path: impl Iterator<Item = &'a MerklePathItem>,
    item: T,
) -> MerkleHash {
    compute_root_from_path(path, CryptoHash::hash_borsh(item))
}

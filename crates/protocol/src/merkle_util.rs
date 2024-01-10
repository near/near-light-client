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
    let mut res = item_hash;
    for item in path {
        match item.direction {
            Direction::Left => {
                res = combine_hash(&item.hash, &res);
            }
            Direction::Right => {
                res = combine_hash(&res, &item.hash);
            }
        }
    }
    res
}

pub fn compute_root_from_path_and_item<'a, T: BorshSerialize>(
    path: impl Iterator<Item = &'a MerklePathItem>,
    item: T,
) -> MerkleHash {
    compute_root_from_path(path, CryptoHash::hash_borsh(item))
}

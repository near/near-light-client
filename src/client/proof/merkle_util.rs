use borsh::BorshSerialize;
use near_primitives::merkle::{combine_hash, Direction, MerklePathItem};
use near_primitives_core::{hash::CryptoHash, types::MerkleHash};

pub trait PathIterator<'a> = Iterator<Item = &'a MerklePathItem>;

pub fn verify_hash<'a>(root: MerkleHash, path: impl PathIterator<'a>, item_hash: MerkleHash) -> bool {
    compute_root_from_path(path, item_hash) == root
}

pub fn compute_root_from_path<'a>(path: impl PathIterator<'a>, item_hash: MerkleHash) -> MerkleHash {
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
    path: impl PathIterator<'a>,
    item: T,
) -> MerkleHash {
    compute_root_from_path(path, CryptoHash::hash_borsh(item))
}

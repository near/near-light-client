use std::{collections::HashMap, sync::Arc};

use super::{LightClientState, Proof as FullProof};
use borsh::{BorshDeserialize, BorshSerialize};
use either::Either;
use itertools::Itertools;
use near_primitives::{
    merkle::{self, combine_hash, compute_root_from_path, MerklePathItem},
    views::LightClientBlockLiteView,
};
use near_primitives_core::hash::CryptoHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct LightweightHeader {
    inner_lite_hash: CryptoHash,
    inner_rest_hash: CryptoHash,
    prev_block_hash: CryptoHash,
    outcome_root: CryptoHash,
}

impl LightweightHeader {
    fn hash(&self) -> CryptoHash {
        combine_hash(
            &combine_hash(&self.inner_lite_hash, &self.inner_rest_hash),
            &self.prev_block_hash,
        )
    }
}

impl From<LightClientBlockLiteView> for LightweightHeader {
    fn from(header: LightClientBlockLiteView) -> Self {
        Self {
            inner_lite_hash: LightClientState::inner_lite_hash(&header.inner_lite),
            inner_rest_hash: header.inner_rest_hash,
            prev_block_hash: header.prev_block_hash,
            outcome_root: header.inner_lite.outcome_root,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct LightestHeader {
    block_hash: CryptoHash,
    outcome_root: CryptoHash,
}

impl From<LightweightHeader> for LightestHeader {
    fn from(header: LightweightHeader) -> Self {
        Self {
            block_hash: header.hash(),
            outcome_root: header.outcome_root,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum Header {
    Lightweight(LightweightHeader),
    Lightest(LightestHeader),
}

impl Header {
    fn hash(&self) -> CryptoHash {
        match self {
            Header::Lightweight(header) => header.hash(),
            Header::Lightest(header) => header.block_hash,
        }
    }
    fn outcome_root(&self) -> CryptoHash {
        match self {
            Header::Lightweight(header) => header.outcome_root,
            Header::Lightest(header) => header.outcome_root,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlindedProof {
    outcome_proof_block_hash: CryptoHash,
    outcome_hash: CryptoHash,
    outcome_proof: Vec<LookupMerklePathItem>,
    outcome_root_proof: Vec<LookupMerklePathItem>,
    block_proof: Vec<LookupMerklePathItem>,
    // The header for the block that this proof was created from
    transaction_header: LightweightHeader,
}

#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
struct MerkleCache {
    items: Vec<MerklePathItem>,
}

impl MerkleCache {
    fn cache(&mut self, batch: &mut Vec<BlindedProof>) {
        // TODO: this is super inneficient, we had a nice one without duplicates but
        // it unfortunately copies the iterator
        let duplicates = batch
            .iter()
            .cloned()
            .map(|fp| [fp.outcome_proof, fp.outcome_root_proof, fp.block_proof].concat())
            .flatten()
            // Unfortunately duplicates clones the array, so we can't do this zero
            // copy
            .duplicates()
            .collect_vec();

        batch
            .iter_mut()
            .map(|fp| {
                fp.outcome_proof
                    .iter_mut()
                    .chain(fp.outcome_root_proof.iter_mut())
                    .chain(fp.block_proof.iter_mut())
            })
            .flatten()
            .for_each(|item| {
                duplicates
                    .iter()
                    .position(|dup| dup == item)
                    .map(|i| item.0 = Either::Left(i as u32));
            });
        self.items = duplicates.into_iter().map(|x| x.0.unwrap_right()).collect();
    }
}

impl From<FullProof> for BlindedProof {
    fn from(x: FullProof) -> Self {
        Self {
            outcome_proof_block_hash: x.outcome_proof.block_hash,
            outcome_hash: CryptoHash::hash_borsh(x.outcome_proof.to_hashes()),
            outcome_proof: x
                .outcome_proof
                .proof
                .into_iter()
                .map(LookupMerklePathItem::from)
                .collect(),
            outcome_root_proof: x
                .outcome_root_proof
                .into_iter()
                .map(LookupMerklePathItem::from)
                .collect(),
            block_proof: x
                .block_proof
                .into_iter()
                .map(LookupMerklePathItem::from)
                .collect(),
            transaction_header: LightweightHeader::from(x.block_header_lite),
        }
    }
}
impl BlindedProof {
    fn collect_path<'a>(
        &self,
        cache: &'a [MerklePathItem],
        path: &[LookupMerklePathItem],
    ) -> Vec<MerklePathItem> {
        Proof::unpack_cached_path(cache, &path)
            .into_iter()
            .cloned()
            .collect()
    }
}

// TODO: add refcount here
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LookupMerklePathItem(
    #[serde(with = "either::serde_untagged")] Either<u32, MerklePathItem>,
);

impl From<MerklePathItem> for LookupMerklePathItem {
    fn from(x: MerklePathItem) -> Self {
        Self(Either::Right(x))
    }
}

impl From<u32> for LookupMerklePathItem {
    fn from(x: u32) -> Self {
        Self(Either::Left(x))
    }
}

impl LookupMerklePathItem {
    fn into<'a>(&'a self, cache: &'a [MerklePathItem]) -> &MerklePathItem {
        match &self.0 {
            // TODO: no panic
            Either::Left(i) => cache.get(*i as usize).unwrap(),
            Either::Right(x) => x,
        }
    }
}

impl From<Either<u32, MerklePathItem>> for LookupMerklePathItem {
    fn from(x: Either<u32, MerklePathItem>) -> Self {
        Self(x)
    }
}

impl std::hash::Hash for LookupMerklePathItem {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(
            match &self.0 {
                Either::Left(t) => CryptoHash::hash_borsh(t),
                Either::Right(u) => CryptoHash::hash_borsh(u),
            }
            .as_bytes(),
        )
    }
}

impl BorshSerialize for LookupMerklePathItem {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match &self.0 {
            Either::Left(_) => BorshSerialize::serialize(&0u8, writer),
            Either::Right(_) => BorshSerialize::serialize(&1u8, writer),
        }?;
        match &self.0 {
            Either::Left(i) => BorshSerialize::serialize(i, writer),
            Either::Right(path) => BorshSerialize::serialize(path, writer),
        }
    }
}

impl BorshDeserialize for LookupMerklePathItem {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let kind = u8::deserialize_reader(reader)?;
        if kind == 0 {
            let i = u32::deserialize_reader(reader)?;
            Ok(LookupMerklePathItem(Either::Left(i)))
        } else if kind == 1 {
            let path = MerklePathItem::deserialize_reader(reader)?;
            Ok(LookupMerklePathItem(Either::Right(path)))
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                anyhow::anyhow!("Invalid LookupMerklePathItem kind: {}", kind),
            ))
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Proof {
    /// The block_merkle_root of the header used to create the proof batch
    /// It should be at least the header for the latest transactions proven + 1
    client_block_merkle_root: CryptoHash,
    batch: Vec<BlindedProof>,
    // common ancestry if there is a common ancestry line in the batch
    // we can save g as costs by only passing this once
    ancestry: Vec<MerklePathItem>,
    // Cache of common paths, indexed by u8
    cache: Vec<MerklePathItem>,
}

impl Proof {
    fn unpack_cached_path<'a>(
        cache: &'a [MerklePathItem],
        path: &'a [LookupMerklePathItem],
    ) -> Vec<&'a MerklePathItem> {
        path.iter().map(|x| x.into(cache)).collect()
    }

    /// This checks the entire path of all batches and updates any reusable nodes
    /// with indices
    // fn cache_nodes(cache: &[MerklePathItem], batch: Vec<FullProof>) -> Vec<BlindedProof> {
    //     batch
    //         .into_iter()
    //         .map(|x| BlindedProof::from(&cache, x))
    //         .collect()
    // }

    fn common_ancestry(
        proof1: &[MerklePathItem],
        proof2: &[MerklePathItem],
    ) -> Vec<MerklePathItem> {
        if proof1.is_empty() {
            return proof2.to_vec();
        }
        if proof2.is_empty() {
            return proof1.to_vec();
        }
        let mut common_ancestry = proof1
            .iter()
            .rev()
            .zip(proof2.iter().rev())
            .peekable()
            .peeking_take_while(|(x, y)| x.hash == y.hash && x.direction == y.direction)
            .map(|(x, _y)| x.clone())
            .collect_vec();
        common_ancestry.reverse();
        common_ancestry
    }

    fn new(created_from: CryptoHash, mut batch: Vec<FullProof>) -> Self {
        // First decide common ancestry among all batches
        let ancestry = batch
            .iter()
            .fold(vec![], |acc, x| Self::common_ancestry(&acc, &x.block_proof));

        // Filter out ancestors
        batch.iter_mut().for_each(|x| {
            x.block_proof = x
                .block_proof
                .iter()
                .filter(|y| !ancestry.contains(y))
                .cloned()
                .collect_vec()
        });

        let mut batch = batch.into_iter().map(BlindedProof::from).collect_vec();
        let mut cache = MerkleCache::default();
        cache.cache(&mut batch);

        Proof {
            client_block_merkle_root: created_from,
            batch,
            ancestry,
            cache: cache.items,
        }
    }
}

pub fn verify_proof(proof: Proof) -> bool {
    // We should know about the known_sync_block_merkle_root
    //assert!(blinded_headers.contains_key(&body.created_from));
    //let cache = Proof::build_flat_cache(&body.batch);

    proof.batch.into_iter().all(|blinded| {
        let block_hash = blinded.transaction_header.hash();
        log::debug!(
            "Verifying blinded proof: {:?}",
            blinded.transaction_header.outcome_root
        );
        let block_hash_matches = block_hash == blinded.outcome_proof_block_hash;

        let outcome_proof_root = compute_root_from_path(
            &blinded.collect_path(&proof.cache, &blinded.outcome_proof),
            blinded.outcome_hash,
        );
        let outcome_root_root = merkle::compute_root_from_path_and_item(
            &blinded.collect_path(&proof.cache, &blinded.outcome_root_proof),
            outcome_proof_root,
        );
        let outcome_verified = outcome_root_root == blinded.transaction_header.outcome_root;

        let mut block_proof: Vec<MerklePathItem> =
            blinded.collect_path(&proof.cache, &blinded.block_proof);
        block_proof.extend_from_slice(&proof.ancestry);

        let block_verified =
            merkle::verify_hash(proof.client_block_merkle_root, &block_proof, block_hash);
        // TODO: here we probably also want to make sure we know about this root

        log::debug!(
            "block_hash_matches: {:?}, outcome_verified: {:?}, block_verified: {:?}",
            block_hash_matches,
            outcome_verified,
            block_verified
        );
        block_hash_matches && outcome_verified && block_verified
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::rpc::{NearRpcClient, Network};
    use futures::FutureExt;
    use near_primitives_core::types::AccountId;
    use std::{path::Path, str::FromStr};

    const BLOCK_MERKLE_ROOT: &str = "WWrLWbWHwSmjtTn5oBZPYgRCuCYn6fkYVa4yhPWNK4L";
    const LIGHT_CLIENT_HEAD: &str = "4bM5eXMDGxpFZXbWNT6TqX1HdZsWoHZ11KerCHJ8RKmU";

    fn get_constants() -> (CryptoHash, CryptoHash, NearRpcClient) {
        let client = NearRpcClient::new(Network::Testnet);
        let block_root = CryptoHash::from_str(BLOCK_MERKLE_ROOT).unwrap();
        let light_client_head = CryptoHash::from_str(LIGHT_CLIENT_HEAD).unwrap();
        (light_client_head, block_root, client)
    }

    fn read_proof<T: for<'a> Deserialize<'a>>(path: &str) -> T {
        println!("Reading {}", path);
        serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap()
    }

    fn write_proof(path: &str, proof: &Proof) {
        std::fs::write(
            path.to_string().replace(".json", ".hex"),
            hex::encode(proof.try_to_vec().unwrap()),
        )
        .unwrap();
        let json = serde_json::to_string_pretty(&proof).unwrap();
        println!("Writing path: {}\n {}", path, json);
        std::fs::write(path, json).unwrap();
    }

    fn proof_fixture(is_new: bool) -> FullProof {
        let path = if is_new {
            "fixtures/new.json"
        } else {
            "fixtures/old.json"
        };
        read_proof(path)
    }

    #[test]
    fn test_blinded_same_block_hash() {
        let proof = proof_fixture(true);
        let full_block_hash = proof.block_header_lite.hash();
        let blinded = LightweightHeader::from(proof.block_header_lite);
        assert_eq!(full_block_hash, blinded.hash());
    }

    #[test]
    fn test_blinded_outcome() {
        let proof = proof_fixture(true);
        let outcome_proof_old = proof.outcome_proof.clone();
        let outcome_proof_leaf = CryptoHash::hash_borsh(proof.outcome_proof.to_hashes());
        let blinded = BlindedProof::from(proof);

        let cache = vec![];
        let outcome_proof_root = merkle::compute_root_from_path(
            &blinded.collect_path(&cache, &blinded.outcome_proof),
            blinded.outcome_hash,
        );
        let outcome_root = merkle::compute_root_from_path_and_item(
            &blinded.collect_path(&cache, &blinded.outcome_root_proof),
            outcome_proof_root,
        );
        assert_eq!(outcome_root, blinded.transaction_header.outcome_root);
        assert_eq!(
            outcome_proof_root,
            merkle::compute_root_from_path(&outcome_proof_old.proof, outcome_proof_leaf)
        )
    }

    #[test]
    fn test_cache() {
        let proof1 = proof_fixture(false);
        let proof2 = proof_fixture(false);

        // Sort the proof items so the order will be the same in  the cache
        let paths = proof2
            .outcome_proof
            .proof
            .iter()
            .chain(&proof2.outcome_root_proof)
            .chain(&proof2.block_proof)
            .cloned()
            .collect_vec();

        let original = vec![proof1, proof2];
        let mut blinded = original.into_iter().map(BlindedProof::from).collect_vec();
        let mut cache = MerkleCache::default();
        cache.cache(&mut blinded);
        // Since the proofs were the same, the cache should contain all of the paths for all of the
        // proofs
        itertools::assert_equal(paths, cache.items);
    }

    #[test]
    fn test_common_ancestry() {
        let proof = proof_fixture(true);
        let cached_nodes = Proof::common_ancestry(&proof.block_proof, &proof.block_proof);
        assert_eq!(cached_nodes, proof.block_proof);
        println!("{:#?}", cached_nodes);
    }

    #[test]
    fn test_create_e2e() {
        let root = CryptoHash::from_str(BLOCK_MERKLE_ROOT).unwrap();

        fn get_proof_len(proof: &FullProof) -> usize {
            let mut bytes = vec![];
            BorshSerialize::serialize(&proof.block_proof, &mut bytes).unwrap();
            BorshSerialize::serialize(&proof.outcome_proof, &mut bytes).unwrap();
            BorshSerialize::serialize(&proof.block_header_lite, &mut bytes).unwrap();
            BorshSerialize::serialize(&proof.outcome_root_proof, &mut bytes).unwrap();
            bytes.len()
        }
        let proof1 = proof_fixture(true);
        let proof2 = proof_fixture(false);
        let proof_size = get_proof_len(&proof1) + get_proof_len(&proof2);
        println!("{:#?}", proof_size);
        let batch = vec![proof1, proof2];
        let proof = Proof::new(root, batch);
        let new_proof_size = proof.try_to_vec().unwrap().len();
        assert!(new_proof_size < proof_size / 2);
        println!("{:#?}", new_proof_size);

        println!("{}", hex::encode(root));
        assert!(verify_proof(proof));
    }

    // Util for rewriting the original bridge proofs
    fn _rewrite_bridge_proofs(rainbow_prover_fixture_path: &str) {
        let rewritten = vec![
            (
                "22f00dd154366d758cd3e4fe81c1caed8e0db6227fe4b2b52a8e5a468aa0a723",
                "proof2.json",
            ),
            (
                "0d0776820a9a81481a559c36fd5d69c33718fb7d7fd3be7564a446e043e2cb35",
                "proof3.json",
            ),
            (
                "1f7129496c461c058fb3daf258d89bf7dacb4efad5742351f66098a00bb6fa53",
                "proof4.json",
            ),
            (
                "a9cd8eb4dd92ba5f2fef47d68e1d73ac8c57047959f6f8a2dcc664419e74e4b8",
                "proof5.json",
            ),
            (
                "cc3954a51b7c1a86861df8809f79c2bf839741e3e380e28360b8b3970a5d90bd",
                "proof6.json",
            ),
            (
                "8298c9cd1048df03e9ccefac4b022636a30a2f7e6a8c33cc4104901b92e08dfd",
                "proof7.json",
            ),
        ]
        .iter()
        .map(|(root, path)| {
            (
                CryptoHash(hex::decode(root).unwrap().try_into().unwrap()),
                format!("{}{}", rainbow_prover_fixture_path, path),
            )
        })
        .all(|(block_root, path)| {
            let proof = if path.contains("old") {
                let proof: FullProof = read_proof(&path);
                Proof::new(block_root, vec![proof])
            } else {
                read_proof(&path)
            };

            write_proof(&path, &proof);
            verify_proof(proof)
        });
        assert!(rewritten);
    }

    // This test populates a reasonably large batch of proofs for verifying the
    // slimmer onchain light client
    #[tokio::test]
    async fn batch_proofs() {
        let _ = pretty_env_logger::try_init();
        let (head, common_root, client) = get_constants();
        let receiver_id = AccountId::from_str("da.topgunbakugo.testnet").unwrap();

        let path = "fixtures/batch.json";

        let p = if Path::new(path).exists() {
            read_proof(path)
        } else {
            // Get a bunch of receipts to test
            let receipts = vec![
                "2QUBErafE2zU3dV9HBYCUyqpcP74erBm7k1j7tXduRa2",
                "BixAd4vjnYKzxNtSLGD5w7jk7vD3ZedesHizutwWvDDK",
                "6W5LXCxFwg21XMxVLqZMzq24g531kFu2hxBr2N5yN67f",
                "Dwwv7KeNP8H9Pr6suUkAqDwex8mp1vK3KykE7asjaYHk",
                "D75Ej8NJ8kYE62CnaVX3p8SCHiNLBQCA7pLpudeRbnM6",
                "ERDrqb65Sa8mKr4XrXCw1uBae3a8mrByLPcEN92zewfG",
                "FuNDcy6u3sS5B8j1szxZGTh6BCjsDTWfUbfFWsFwUyPA",
                "2EVVdVsw1nM3hRFV4LTkBYYRWPCR77TVmYxZwipLHmYn",
                "9Exwa5z51bTGWPzMMkRcVdGZ6a8rpu4CuWfAvrMuqXHn",
                "J65AycXr48nCqrRc8eErLp5AiQb6xUAWF1sgG2fRbn9t",
                "5axBiFL3GkvizK4KobsJjzychu7UckoKACnX23RefhoS",
                "GEG9nhhwbgMHw61fTrFYvtpeRidAB6NKmNFJmkMc8AuE",
                "BFdir5jFtyWQWoLPbxWEGtRedbjgt4nSPcDrdNfWLXcd",
                "48tF8CXXLLaUgEbvayqhvX1UZLzLrqSjVJBq5bWXFX7T",
                "3L2vmfXBZzMGoXx8bLDaSRxtp2dV65SZr3rYKM46wqe1",
                "4g3zeZEt4UrXqFh8Vxcdz8UCGaBBdT7K7MELrnNbu3PH",
                "2r652tQLr8kpGtY6KQNLhVC4j6S5jwC1Q6VcuLxQM1UQ",
                "DNAQsgrEqJ6kYhqaXbhCNP5W4K891jLUhBtY3nsU17dv",
                "EJCfAgRT3x8hPmTvLJgqexuwRqhgujUKbby4b81ypXX4",
                "3FFWvbPQXkpQNvGwJ6NkkJtya6XXo8x88Wmhoyv6ABQU",
                "BVgDgRBcJJoXeFYarSTrsH9NYe6kgfC14Des88hSJp1j",
                "EcnvcNZDgwyiBP7NpV2afkDDvPCmw5rwKT2MLiG1jUFD",
                "Hbjut1evHnfm1Ee9eeGJe5ydorVE3W66RacprLuciFpY",
                "AKknXHv6Y7iyD44yyTjdTLmgC8AM9CmUHtLXvgEh4qdS",
            ]
            .into_iter()
            .map(CryptoHash::from_str)
            .map(Result::unwrap)
            .map(|receipt_id| {
                client
                    .fetch_light_client_receipt_proof(receipt_id.clone(), receiver_id.clone(), head)
                    .map(Option::unwrap)
            })
            .collect_vec();

            let proofs: Vec<_> = futures::future::join_all(receipts).await;

            let p = Proof::new(common_root, proofs);
            write_proof(path, &p);
            p
        };

        assert!(verify_proof(p));
    }
}

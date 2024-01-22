use derive_more::AsRef;
use derive_more::Into;
use near_light_client_protocol::{
    prelude::{BasicProof, Header, Itertools},
    LightClientBlockView, Protocol, StakeInfo, ValidatorStake,
};
pub use near_primitives::hash::CryptoHash;
pub use pretty_assertions::assert_eq as pas_eq;
pub use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Into)]
pub struct LightClientFixture<T> {
    pub last_block_hash: CryptoHash,
    pub body: T,
}

pub fn fixture<T: DeserializeOwned>(file: &str) -> T {
    serde_json::from_reader(std::fs::File::open(format!("../../fixtures/{}", file)).unwrap())
        .unwrap()
}

pub fn lc<T: DeserializeOwned>(file: &str) -> LightClientFixture<T> {
    fixture(file)
}

pub fn main_last() -> LightClientFixture<LightClientBlockView> {
    lc("main_2.json")
}

pub fn main_next() -> LightClientFixture<LightClientBlockView> {
    lc("main_1.json")
}

pub fn main_first() -> LightClientFixture<LightClientBlockView> {
    lc("main_0.json")
}

pub fn test_last() -> LightClientFixture<LightClientBlockView> {
    lc("test_2.json")
}

pub fn test_next() -> LightClientFixture<LightClientBlockView> {
    lc("test_1.json")
}

pub fn test_first() -> LightClientFixture<LightClientBlockView> {
    lc("test_0.json")
}

pub fn view_to_lite_view(h: LightClientBlockView) -> Header {
    Header {
        prev_block_hash: h.prev_block_hash,
        inner_rest_hash: h.inner_rest_hash,
        inner_lite: h.inner_lite,
    }
}

pub fn mainnet_state() -> (Header, Vec<ValidatorStake>, LightClientBlockView) {
    pretty_env_logger::try_init().ok();
    let first = main_first().body;
    let head = view_to_lite_view(first.clone());
    let bps = first
        .next_bps
        .unwrap()
        .into_iter()
        .map(Into::into)
        .collect();
    let next = main_next();

    (head.into(), bps, next.body)
}

pub fn testnet_state() -> (Header, Vec<ValidatorStake>, LightClientBlockView) {
    pretty_env_logger::try_init().ok();
    let first = test_first().body;
    let head = view_to_lite_view(first.clone());
    let bps = first
        .next_bps
        .unwrap()
        .into_iter()
        .map(Into::into)
        .collect();
    let next = test_next();

    (head.into(), bps, next.body)
}

pub fn test_state() -> (Header, Vec<ValidatorStake>, LightClientBlockView) {
    mainnet_state()
}

pub fn to_header(bv: LightClientBlockView) -> Header {
    Header {
        prev_block_hash: bv.prev_block_hash,
        inner_rest_hash: bv.inner_rest_hash,
        inner_lite: bv.inner_lite,
    }
}

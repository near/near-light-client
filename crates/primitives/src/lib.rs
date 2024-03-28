pub mod config;

use near_primitives_core::types::AccountId;

// https://github.com/near/nearcore/blob/master/nearcore/src/config.rs#L133C1-L134C1
// TODO: expose this from NP, currently this is a risk that the light client
// could be exploited if the max seats changes without knowing
pub const NUM_BLOCK_PRODUCER_SEATS: usize = 50;

// Used by nearcore to determine the end of the account in the state trie.
pub const ACCOUNT_DATA_SEPARATOR: u8 = b',';

pub fn pad_account_id(account_id: &AccountId) -> [u8; AccountId::MAX_LEN] {
    let account_id = account_id.as_str().as_bytes().to_vec();
    pad_account_bytes(account_id)
}

pub fn pad_account_bytes(mut account_id: Vec<u8>) -> [u8; AccountId::MAX_LEN] {
    account_id.resize(AccountId::MAX_LEN, ACCOUNT_DATA_SEPARATOR);
    account_id.try_into().expect("invalid account bytes")
}

pub mod prelude {
    pub use super::config::{BaseConfig, Configurable};
}

pub use anyhow::{anyhow, Result};
pub use futures::{FutureExt, TryFutureExt};
pub use itertools::Itertools;
pub use log::{debug, error, info, trace, warn};
pub use near_primitives::types::AccountId;
use near_primitives::types::TransactionOrReceiptId;
pub use near_primitives_core::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    hash::CryptoHash,
};
pub use serde::{Deserialize, Serialize};

pub type Header = near_primitives::views::LightClientBlockLiteView;
pub type BasicProof =
    near_jsonrpc_primitives::types::light_client::RpcLightClientExecutionProofResponse;
pub type GetProof = TransactionOrReceiptId;

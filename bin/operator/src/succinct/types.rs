use alloy::{
    primitives::*, providers::network::Ethereum, sol, sol_types::SolCall, transports::http::Http,
};
use near_light_client_primitives::pad_account_id;
pub use near_light_client_rpc::TransactionOrReceiptId as TransactionOrReceiptIdPrimitive;
use near_light_clientx::plonky2x::backend::{
    circuit::DefaultParameters,
    function::{ProofRequest, ProofResult},
    prover::ProofId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use NearX::TransactionOrReceiptId;

use self::NearX::NearXInstance;
use crate::types::NearX::{syncCall, verifyCall};

pub type NearXClient = NearXInstance<Ethereum, Http<reqwest::Client>, super::Provider>;

// TODO: update ABI when updating contract, can we just pass the path of the
// contract now we use alloy?
sol!(
    #[sol(abi, rpc)]
    NearX,
    "../../nearx/contract/abi.json"
);

/// The circuits we support in this nearxclient
pub enum Circuit {
    Sync,
    Verify,
}
impl Circuit {
    fn selector(&self) -> [u8; 4] {
        match self {
            Circuit::Sync => syncCall::SELECTOR,
            Circuit::Verify => verifyCall::SELECTOR,
        }
    }

    /// Writes the input prepended with the selector
    pub fn with_selector(&self, input: &[u8]) -> Vec<u8> {
        vec![&self.selector()[..], input].concat()
    }

    /// Get the function id from the contract
    /// This can be updated in realtime, so we query this every time without
    /// caching
    pub async fn function_id(&self, client: &NearXClient) -> anyhow::Result<[u8; 32]> {
        let id = match self {
            Circuit::Sync => client.syncFunctionId().call().await.map(|x| x._0),
            Circuit::Verify => client.verifyFunctionId().call().await.map(|x| x._0),
        }?;
        Ok(*id)
    }

    /// Filter a deployment from the release list
    /// Safety: panics when a deployment cannot be found
    pub fn deployment(&self, releases: &[Deployment]) -> Deployment {
        log::debug!("finding deployment in {:?}", releases);
        let find = |entrypoint: &str| -> Deployment {
            log::debug!("finding deployment for {}", entrypoint);
            releases
                .iter()
                .find(|r| r.release_info.release.entrypoint == entrypoint)
                .unwrap_or_else(|| panic!("could not find release for entrypoint {entrypoint}"))
                .to_owned()
        };
        match self {
            Circuit::Sync => find("sync"),
            Circuit::Verify => find("verify"),
        }
    }
}

// Eventually we can get these types from succinct crate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequestResponse {
    pub proof_id: ProofId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    pub id: Uuid,
    pub status: ProofStatus,
    pub proof_request: ProofRequest<DefaultParameters, 2>,
    pub result: Option<ProofResult<DefaultParameters, 2>>,
    pub edges: ProofEdges,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofEdges {
    #[serde(default)]
    pub requests: Vec<Request>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofStatus {
    Success,
    Failure,
    Running,
    Requested,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deployment {
    pub id: u32,
    pub address: Address,
    pub chain_id: u32,
    pub function_id: String,
    pub owner: Address,
    pub gateway: Address,
    pub tx_hash: TxHash,
    #[serde(rename = "edges")]
    pub release_info: DeploymentEdges,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeploymentEdges {
    pub release: Release,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Release {
    pub id: String,
    pub number: u64,
    pub name: String,
    #[serde(rename = "project_id")]
    pub project_id: String,
    pub entrypoint: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
}

impl From<TransactionOrReceiptIdPrimitive> for TransactionOrReceiptId {
    fn from(value: TransactionOrReceiptIdPrimitive) -> Self {
        let (id, account, is_transaction) = match value {
            TransactionOrReceiptIdPrimitive::Transaction {
                transaction_hash,
                sender_id,
            } => (transaction_hash, sender_id, true),
            TransactionOrReceiptIdPrimitive::Receipt {
                receipt_id,
                receiver_id,
            } => (receipt_id, receiver_id, false),
        };
        TransactionOrReceiptId {
            id: id.0.into(),
            account: pad_account_id(&account).into(),
            isTransaction: is_transaction,
        }
    }
}

#[cfg(test)]
mod tests {
    use test_utils::fixture;

    use super::*;

    // TODO: integration tests
    #[test]
    fn test_deserialise_deployments() {
        let _ = fixture::<Vec<Deployment>>("deployments.json");
    }
    #[test]
    fn test_deserialise_sync_proof() {
        let _proof = fixture::<ProofResponse>("sync_proof.json");
    }
    #[test]
    fn test_deserialise_verify_proof() {
        let _proof = fixture::<ProofResponse>("verify_proof.json");
    }
}

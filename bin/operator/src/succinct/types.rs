use ethers::{abi::AbiEncode, contract::abigen, prelude::*};
pub use near_light_client_rpc::TransactionOrReceiptId as TransactionOrReceiptIdPrimitive;
use plonky2x::backend::{
    circuit::DefaultParameters,
    function::{ProofRequest, ProofResult},
    prover::ProofId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

abigen!(
    NearX,
    "../../nearx/contract/abi.json",
    derives(serde::Deserialize, serde::Serialize),
);

/// The circuits we support in this nearxclient
pub enum Circuit {
    Sync,
    Verify,
}
impl Circuit {
    pub fn as_function_selector(&self) -> Vec<u8> {
        match self {
            Circuit::Sync => SyncFunctionIdCall {}.encode(),
            Circuit::Verify => VerifyFunctionIdCall {}.encode(),
        }
    }
    pub async fn function_id(&self, client: &NearX<Provider<Http>>) -> anyhow::Result<[u8; 32]> {
        let id = match self {
            Circuit::Sync => client.sync_function_id(),
            Circuit::Verify => client.verify_function_id(),
        }
        .await?;
        Ok(id)
    }
    pub fn deployment(&self, releases: &[Deployment]) -> Deployment {
        let find = |entrypoint: &str| -> Deployment {
            releases
                .iter()
                .find(|r| r.release_info.release.entrypoint == entrypoint)
                .expect(&format!(
                    "could not find release for entrypoint {entrypoint}"
                ))
                .to_owned()
        };
        match self {
            Circuit::Sync => find("sync"),
            Circuit::Verify => find("verify"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequestResponse {
    pub proof_id: ProofId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    pub id: Uuid,
    pub status: ProofStatus,
    pub proof_request: ProofRequest<DefaultParameters, 2>,
    pub request_hash: [u8; 32],
    pub result: ProofResult<DefaultParameters, 2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofStatus {
    Success,
    Failure,
    Running,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deployment {
    pub id: u32,
    pub address: Address,
    pub chain_id: u32,
    pub function_id: String,
    pub owner: Address,
    pub gateway: Address,
    pub tx_hash: H256,
    #[serde(rename = "edges")]
    pub release_info: Edges,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edges {
    pub release: Release,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Release {
    pub id: String,
    pub number: i64,
    pub name: String,
    #[serde(rename = "project_id")]
    pub project_id: String,
    pub entrypoint: String,
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
            id: id.0,
            account: near_light_client_protocol::config::pad_account_id(&account).into(),
            is_transaction,
        }
    }
}

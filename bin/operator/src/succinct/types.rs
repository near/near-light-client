use ethers::types::{Address, H256};
use plonky2x::backend::{
    circuit::DefaultParameters,
    function::{ProofRequest, ProofResult},
    prover::ProofId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

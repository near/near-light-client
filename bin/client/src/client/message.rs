use super::{protocol::experimental::Proof as ExperimentalProof, Header, Proof};
use crate::prelude::*;
use coerce::actor::message::Message;
use near_primitives::types::TransactionOrReceiptId;

pub struct Shutdown;

impl Message for Shutdown {
    type Result = Result<()>;
}

pub struct Head;

impl Message for Head {
    type Result = Option<Header>;
}

pub struct Archive {
    pub epoch: CryptoHash,
}

impl Message for Archive {
    type Result = Option<Header>;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetProof(pub TransactionOrReceiptId);

impl Message for GetProof {
    type Result = Option<super::Proof>;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BatchGetProof(pub Vec<GetProof>);

impl Message for BatchGetProof {
    type Result = Option<(ExperimentalProof, Vec<anyhow::Error>)>;
}

pub struct VerifyProof {
    pub proof: Proof,
}

impl Message for VerifyProof {
    type Result = Result<bool>;
}

// TODO: batch messages
//
//
#[cfg(test)]
mod tests {

    #[test]
    fn test_name() {}
}

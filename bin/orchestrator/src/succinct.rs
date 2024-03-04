use std::str::FromStr;

use ethers::prelude::*;
use near_light_client_rpc::{
    prelude::{CryptoHash, Itertools},
    TransactionOrReceiptId as TransactionOrReceiptIdPrimitive,
};
use plonky2x::backend::{
    circuit::DefaultParameters,
    function::{BytesRequestData, ProofRequest, ProofRequestBase, ProofResult},
    prover::ProofId,
};
use reqwest::header::{self, HeaderMap};
use reqwest_middleware::RequestBuilder;
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};

use crate::config;

abigen!(
    NearX,
    "../../nearx/contract/abi.json",
    derives(serde::Deserialize, serde::Serialize),
);

#[derive(Clone)]
pub struct Client {
    host: String,
    sync_release_id: String,
    verify_release_id: String,
    inner: reqwest_middleware::ClientWithMiddleware,
}

impl Client {
    pub fn new(config: &config::Config) -> Self {
        let mut headers = HeaderMap::new();
        let mut auth = header::HeaderValue::from_str(&config.succinct_api_key).unwrap();
        auth.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth);

        let inner = reqwest::ClientBuilder::default()
            .timeout(std::time::Duration::from_secs(2))
            .default_headers(headers)
            .build()
            .unwrap();

        // Retry up to 3 times with increasing intervals between attempts.
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let inner = reqwest_middleware::ClientBuilder::new(inner)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Self {
            host: config.succinct_host.clone(),
            sync_release_id: config.succinct_sync_release_id.clone(),
            verify_release_id: config.succinct_verify_release_id.clone(),
            inner,
        }
    }
    pub fn build_sync_request(
        &self,
        trusted_header_hash: CryptoHash,
    ) -> ProofRequest<DefaultParameters, 2> {
        ProofRequest::<DefaultParameters, 2>::Bytes(ProofRequestBase {
            release_id: self.sync_release_id.clone(),
            parent_id: None,
            files: None,
            data: BytesRequestData {
                input: trusted_header_hash.0.to_vec(),
            },
        })
    }
    pub fn build_verify_request(
        &self,
        trusted_header_hash: CryptoHash,
        ids: Vec<TransactionOrReceiptIdPrimitive>,
    ) -> ProofRequest<DefaultParameters, 2> {
        ProofRequest::<DefaultParameters, 2>::Bytes(ProofRequestBase {
            release_id: self.verify_release_id.clone(),
            parent_id: None,
            files: None,
            data: BytesRequestData {
                input: vec![
                    trusted_header_hash.0.to_vec(),
                    ethers::abi::encode_packed(
                        &ids.into_iter()
                            .map(TransactionOrReceiptId::from)
                            .flat_map(ethers::abi::Tokenize::into_tokens)
                            .collect_vec(),
                    )
                    .unwrap(),
                ]
                .concat(),
            },
        })
    }
    pub async fn send(
        &self,
        request: ProofRequest<DefaultParameters, 2>,
    ) -> anyhow::Result<ProofId> {
        let res = self
            .inner
            .post(format!("{}/proof/new", self.host))
            .json(&request)
            .send()
            .await?
            .error_for_status()?;
        let r: ProofId = res.json().await?;
        Ok(r)
    }
    pub async fn get(
        &self,
        proof_id: ProofId,
    ) -> anyhow::Result<ProofResult<DefaultParameters, 2>> {
        let res = self
            .inner
            .get(format!("{}/proof/{}", self.host, proof_id.0))
            .send()
            .await?
            .error_for_status()?;
        let r: ProofResult<DefaultParameters, 2> = res.json().await?;
        Ok(r)
    }
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

#[cfg(test)]
mod tests {
    use plonky2x::utils::{bytes, serde::deserialize_hex};

    use super::*;

    fn test_config() -> config::Config {
        config::Config::new().unwrap()
    }

    #[test]
    fn test_can_build_sync() {
        let release = "1cde66c3-46df-4aab-8409-4cbb97abee1c".to_string();
        let trusted_header_hash: [u8; 32] =
            bytes!("63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3");
        let trusted_header_hash = CryptoHash(trusted_header_hash);

        let mut client: Client = Client::new(&test_config());
        client.sync_release_id = release;

        let req = client.build_sync_request(trusted_header_hash);
        println!("{}", serde_json::to_string_pretty(&req).unwrap());
    }

    #[test]
    fn test_can_build_verify() {}
}

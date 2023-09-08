use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use flume::Sender;
use near_primitives_core::hash::CryptoHash;
use rust_kzg_blst::types::kzg_settings::FsKZGSettings;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::client::Message;

type ClientState = flume::Sender<Message>;

pub(crate) fn init(
    ctx: Sender<Message>,
    trusted_setup: Arc<FsKZGSettings>,
) -> JoinHandle<Result<(), axum::Error>> {
    let proof_channel = flume::bounded(64);

    let controller = Router::new()
        .route("/head", get(header::get_head))
        .with_state((ctx.clone(), flume::bounded(64)))
        .route("/header/:epoch", get(header::get_by_epoch))
        .with_state((ctx.clone(), flume::bounded(64)))
        .route(
            "/proof/tx/:transaction_id/:sender_id",
            get(proof::get_tx_proof),
        )
        .with_state((ctx.clone(), proof_channel.clone()))
        .route(
            "/proof/receipt/:receipt_id/:receiver_id",
            get(proof::get_receipt_proof),
        )
        .with_state((ctx.clone(), proof_channel))
        .route("/proof", post(proof::post_proof))
        .with_state((ctx.clone(), flume::bounded(64)))
        .route("/blob/encode", post(erasure::encode))
        .with_state(trusted_setup.clone())
        .route("/blob/decode", post(erasure::decode))
        .with_state(trusted_setup.clone())
        .route("/blob/commit", post(erasure::commit))
        .with_state(trusted_setup.clone())
        .route("/blob/commit/prove", post(erasure::prove_commitment))
        .with_state(trusted_setup.clone())
        .route("/blob/commit/verify", post(erasure::verify_proof))
        .with_state(trusted_setup.clone());

    tokio::spawn(async {
        let r = axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .serve(controller.into_make_service())
            .await;
        r.map_err(|e| todo!("{:?}", e))
    })
}

mod header {
    use super::*;
    use near_primitives::views::LightClientBlockLiteView;

    pub type HeadChannel = (
        flume::Sender<LightClientBlockLiteView>,
        flume::Receiver<LightClientBlockLiteView>,
    );

    pub type HeaderChannel = (
        flume::Sender<Option<LightClientBlockLiteView>>,
        flume::Receiver<Option<LightClientBlockLiteView>>,
    );

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Params {
        epoch: CryptoHash,
    }

    pub(super) async fn get_by_epoch(
        State((client, (tx, rx))): State<(ClientState, HeaderChannel)>,
        Path(params): Path<Params>,
    ) -> impl IntoResponse {
        log::debug!("get_by_epoch: {:?}", params);
        if let Err(e) = client
            .send_async(Message::Archive {
                tx,
                epoch: params.epoch,
            })
            .await
        {
            log::error!("Failed to send get_by_epoch: {:?}", e);
        }

        rx.recv_async().await.map(axum::Json).map_err(|_| {
            log::error!("Failed to receive result, channel closed");
            internal_server_error()
        })
    }

    pub(super) async fn get_head(
        State((client, (tx, rx))): State<(ClientState, HeadChannel)>,
    ) -> impl IntoResponse {
        log::debug!("get_head");
        if let Err(e) = client.send_async(Message::Head { tx }).await {
            log::error!("Failed to send get_head: {:?}", e);
        }

        rx.recv_async().await.map(axum::Json).map_err(|_| {
            log::error!("Failed to receive result, channel closed");
            internal_server_error()
        })
    }
}

mod proof {
    use super::*;
    use crate::client::{Proof, ProofType};
    use axum::Json;
    use near_jsonrpc_client::methods::light_client_proof::RpcLightClientExecutionProofResponse;
    use near_primitives_core::types::AccountId;

    pub type ProofChannel = (flume::Sender<Option<Proof>>, flume::Receiver<Option<Proof>>);
    pub type ValidateProofChannel = (flume::Sender<bool>, flume::Receiver<bool>);

    #[derive(Debug, Deserialize, Serialize)]
    pub struct TransactionParams {
        transaction_id: CryptoHash,
        sender_id: AccountId,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ReceiptParams {
        receipt_id: CryptoHash,
        receiver_id: AccountId,
    }

    pub(super) async fn get_tx_proof(
        State((client, (tx, rx))): State<(ClientState, ProofChannel)>,
        Path(params): Path<TransactionParams>,
    ) -> impl IntoResponse {
        log::debug!("get_proof: {:?}", params);
        if let Err(e) = client
            .send_async(Message::GetProof {
                tx,
                proof: ProofType::Transaction {
                    transaction_id: params.transaction_id,
                    sender_id: params.sender_id,
                },
            })
            .await
        {
            log::error!("Failed to send get_proof: {:?}", e);
        }
        rx.recv_async().await.map(axum::Json).map_err(|_| {
            log::error!("Failed to receive result, channel closed");
            internal_server_error()
        })
    }

    pub(super) async fn get_receipt_proof(
        State((client, (tx, rx))): State<(ClientState, ProofChannel)>,
        Path(params): Path<ReceiptParams>,
    ) -> impl IntoResponse {
        log::debug!("get_proof: {:?}", params);
        if let Err(e) = client
            .send_async(Message::GetProof {
                tx,
                proof: ProofType::Receipt {
                    receipt_id: params.receipt_id,
                    receiver_id: params.receiver_id,
                },
            })
            .await
        {
            log::error!("Failed to send get_proof: {:?}", e);
        }
        rx.recv_async().await.map(axum::Json).map_err(|_| {
            log::error!("Failed to receive result, channel closed");
            internal_server_error()
        })
    }

    pub(super) async fn post_proof(
        State((client, (tx, rx))): State<(ClientState, ValidateProofChannel)>,
        Json(proof): Json<RpcLightClientExecutionProofResponse>,
    ) -> impl IntoResponse {
        log::debug!("post_proof: {:?}", proof);
        if let Err(e) = client
            .send_async(Message::ValidateProof { tx, proof })
            .await
        {
            log::error!("Failed to send post_proof: {:?}", e);
        }

        rx.recv_async().await.map(axum::Json).map_err(|_| {
            log::error!("Failed to receive result, channel closed");
            internal_server_error()
        })
    }
}

mod erasure {
    use axum::Json;
    use kzg::{Fr, G1};
    use rust_kzg_blst::types::{fr::FsFr, g1::FsG1};

    use super::*;
    use crate::erasure::{
        commit::{Commitment, CommitmentExternal, Proof, ProofExternal},
        BlobData, ExternalErasure,
    };

    const VALIDATORS: usize = 4096;

    pub(super) async fn encode(Json(blobs): Json<BlobData>) -> impl IntoResponse {
        log::debug!("encode blobs {:?}", blobs);
        crate::erasure::Erasure::<VALIDATORS>::encodify(&blobs.data)
            .map(|encoded| {
                axum::Json(ExternalErasure {
                    shards: encoded.shards_to_bytes(),
                })
            })
            .map_err(|e| {
                log::error!("Failed to encode: {:?}", e);
                internal_server_error()
            })
    }

    pub(super) async fn decode(Json(blobs): Json<ExternalErasure>) -> impl IntoResponse {
        log::debug!("decode blobs {:?}", blobs);
        crate::erasure::Erasure::<VALIDATORS>::from(blobs)
            .recover()
            .map(|recovered| axum::Json(BlobData { data: recovered }))
            .map_err(|e| {
                log::error!("Failed to encode: {:?}", e);
                internal_server_error()
            })
    }

    pub(super) async fn commit(
        State(ts): State<Arc<FsKZGSettings>>,
        Json(blobs): Json<ExternalErasure>,
    ) -> impl IntoResponse {
        log::debug!("commit blobs {:?}", blobs);
        let erasure = crate::erasure::Erasure::<VALIDATORS>::from(blobs);
        erasure
            .encoded_to_commitment(ts)
            .map(|c| axum::Json(CommitmentExternal::from(c)))
            .map_err(|e| {
                log::error!("Failed to encode: {:?}", e);
                internal_server_error()
            })
    }
    // TODO: these endpoints shouldnt be decoding from request, refactor to From/Tryfrom in the
    // module
    // TODO: remove panics
    pub(super) async fn prove_commitment(
        State(ts): State<Arc<FsKZGSettings>>,
        Json(c): Json<CommitmentExternal>,
    ) -> impl IntoResponse {
        log::debug!("prove commitment {:?}", c);
        let proofs = crate::erasure::Erasure::<VALIDATORS>::prove_commitment(
            Commitment {
                commitment: FsG1::from_bytes(&c.commitment[..]).unwrap(),
                blob: c
                    .blob
                    .iter()
                    .map(|b| FsFr::from_bytes(&b[..]).unwrap())
                    .collect(),
            },
            ts,
        );
        axum::Json(
            proofs
                .into_iter()
                .map(ProofExternal::from)
                .collect::<Vec<_>>(),
        )
    }

    pub(super) async fn verify_proof(
        State(ts): State<Arc<FsKZGSettings>>,
        Json(c): Json<Vec<ProofExternal>>,
    ) -> impl IntoResponse {
        log::debug!("prove commitment {:?}", c);
        let batches: Vec<Proof> = c
            .into_iter()
            .map(|c| {
                (Proof {
                    proof: FsG1::from_bytes(&c.proof[..]).unwrap(),
                    z_fr: FsFr::from_bytes(&c.z_fr[..]).unwrap(),
                    y_fr: FsFr::from_bytes(&c.y_fr[..]).unwrap(),
                    commitment: FsG1::from_bytes(&c.commitment[..]).unwrap(),
                })
            })
            .collect();

        let verified = crate::erasure::Erasure::<VALIDATORS>::verify_proof(&batches, ts);
        axum::Json(verified)
    }
}

fn internal_server_error() -> impl IntoResponse {
    let mut r = Response::new("Error".to_string());
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
}

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use flume::Sender;
use near_primitives_core::hash::CryptoHash;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::client::Message;

type ClientState = flume::Sender<Message>;

pub(crate) fn init(ctx: Sender<Message>) -> JoinHandle<Result<(), axum::Error>> {
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
        .with_state((ctx.clone(), flume::bounded(64)));

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
    pub struct Params {
        transaction_id: CryptoHash,
        sender_id: AccountId,
    }

    pub(super) async fn get_tx_proof(
        State((client, (tx, rx))): State<(ClientState, ProofChannel)>,
        Path(params): Path<Params>,
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
        Path(params): Path<Params>,
    ) -> impl IntoResponse {
        log::debug!("get_proof: {:?}", params);
        if let Err(e) = client
            .send_async(Message::GetProof {
                tx,
                proof: ProofType::Receipt {
                    receipt_id: params.transaction_id,
                    receiver_id: params.sender_id,
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

fn internal_server_error() -> impl IntoResponse {
    let mut r = Response::new("Error".to_string());
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
}

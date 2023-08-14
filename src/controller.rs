use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use flume::Sender;
use near_primitives_core::hash::CryptoHash;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::client::Message;

// TODO: refactor to channels, call the client with a oneshot channel

type ClientState = flume::Sender<Message>;

pub(crate) fn init(ctx: Sender<Message>) -> JoinHandle<Result<(), axum::Error>> {
    let controller = Router::new()
        .route("/head", get(header::get_head))
        .with_state(ctx.clone())
        .route("/header/:epoch", get(header::get_by_epoch))
        .with_state(ctx.clone())
        .route("/proof/:transaction_id/:sender_id", get(proof::get_proof))
        .with_state(ctx.clone())
        .route("/proof", post(proof::post_proof))
        .with_state(ctx.clone());

    tokio::spawn(async {
        let r = axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .serve(controller.into_make_service())
            .await;
        r.map_err(|e| todo!("{:?}", e))
    })
}

mod header {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Params {
        epoch: CryptoHash,
    }

    pub(super) async fn get_by_epoch(
        State(client): State<ClientState>,
        Path(params): Path<Params>,
    ) -> impl IntoResponse {
        log::info!("get_by_epoch: {:?}", params);
        let (tx, rx) = flume::bounded(1);
        client
            .send_async(Message::Archive {
                tx,
                epoch: params.epoch,
            })
            .await;

        axum::Json(rx.recv_async().await.expect("Failed to recv"))
    }

    pub(super) async fn get_head(State(client): State<ClientState>) -> impl IntoResponse {
        log::info!("get_head");
        let (tx, rx) = flume::bounded(1);
        client.send_async(Message::Head { tx }).await;

        axum::Json(rx.recv_async().await.expect("Failed to recv"))
    }
}

mod proof {
    use super::*;
    use axum::Json;
    use near_jsonrpc_client::methods::light_client_proof::RpcLightClientExecutionProofResponse;
    use near_primitives_core::types::AccountId;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Params {
        transaction_id: CryptoHash,
        sender_id: AccountId,
    }

    pub(super) async fn get_proof(
        State(client): State<ClientState>,
        Path(params): Path<Params>,
    ) -> impl IntoResponse {
        log::info!("get_proof: {:?}", params);
        let (tx, rx) = flume::bounded(1);
        client
            .send_async(Message::GetProof {
                tx,
                transaction_id: params.transaction_id,
                sender_id: params.sender_id,
            })
            .await;

        axum::Json(rx.recv_async().await.expect("Failed to recv"))
    }

    pub(super) async fn post_proof(
        State(client): State<ClientState>,
        Json(proof): Json<RpcLightClientExecutionProofResponse>,
    ) -> impl IntoResponse {
        log::info!("post_proof: {:?}", proof);
        let (tx, rx) = flume::bounded(1);
        client
            .send_async(Message::ValidateProof { tx, proof })
            .await;

        axum::Json(rx.recv_async().await.expect("Failed to recv"))
    }
}

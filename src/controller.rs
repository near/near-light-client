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
        .with_state((ctx.clone(), flume::bounded(32)))
        .route("/header/:epoch", get(header::get_by_epoch))
        .with_state((ctx.clone(), flume::bounded(32)))
        .route("/proof/:transaction_id/:sender_id", get(proof::get_proof))
        .with_state((ctx.clone(), flume::bounded(32)))
        .route("/proof", post(proof::post_proof))
        .with_state((ctx.clone(), flume::bounded(32)));

    tokio::spawn(async {
        let r = axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .serve(controller.into_make_service())
            .await;
        r.map_err(|e| todo!("{:?}", e))
    })
}

mod header {
    use near_primitives::views::LightClientBlockLiteView;

    use super::*;

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
        log::info!("get_by_epoch: {:?}", params);
        client
            .send_async(Message::Archive {
                tx,
                epoch: params.epoch,
            })
            .await;

        axum::Json(rx.recv_async().await.expect("Failed to recv"))
    }

    pub(super) async fn get_head(
        State((client, (tx, rx))): State<(ClientState, HeadChannel)>,
    ) -> impl IntoResponse {
        log::info!("get_head");
        client.send_async(Message::Head { tx }).await;

        axum::Json(rx.recv_async().await.expect("Failed to recv"))
    }
}

mod proof {
    use crate::client::Proof;

    use super::*;
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

    pub(super) async fn get_proof(
        State((client, (tx, rx))): State<(ClientState, ProofChannel)>,
        Path(params): Path<Params>,
    ) -> impl IntoResponse {
        log::info!("get_proof: {:?}", params);
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
        State((client, (tx, rx))): State<(ClientState, ValidateProofChannel)>,
        Json(proof): Json<RpcLightClientExecutionProofResponse>,
    ) -> impl IntoResponse {
        log::info!("post_proof: {:?}", proof);
        client
            .send_async(Message::ValidateProof { tx, proof })
            .await;

        axum::Json(rx.recv_async().await.expect("Failed to recv"))
    }
}

use std::sync::Arc;

use crate::client::LightClient;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use near_primitives_core::hash::CryptoHash;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

type ClientState = Arc<LightClient>;

// TODO: refactor to channels, call the client with a oneshot channel

pub(crate) fn init(client: ClientState) -> JoinHandle<Result<(), axum::Error>> {
    let controller = Router::new()
        .route("/head", get(header::get_head))
        .with_state(client.clone())
        .route("/header/:epoch", get(header::get_by_epoch))
        .with_state(client.clone())
        .route("/proof/:transaction_id/:sender_id", get(proof::get_proof))
        .with_state(client.clone())
        .route("/proof", post(proof::post_proof))
        .with_state(client.clone());

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
        axum::Json(client.header(params.epoch).cloned())
    }

    pub(super) async fn get_head(State(client): State<ClientState>) -> impl IntoResponse {
        axum::Json(client.head().await)
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
        axum::Json(
            client
                .get_proof(params.transaction_id, params.sender_id)
                .await,
        )
    }

    pub(super) async fn post_proof(
        State(client): State<ClientState>,
        Json(body): Json<RpcLightClientExecutionProofResponse>,
    ) -> impl IntoResponse {
        axum::Json(client.validate_proof(body).await)
    }
}

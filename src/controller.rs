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

pub(crate) fn init(client: &LightClient) -> JoinHandle<Result<(), axum::Error>> {
    let controller = Router::new()
        .route("/head", get(header::get_head))
        .with_state(client.clone())
        .route("/header/:epoch", get(header::get_by_epoch))
        .with_state(client.clone())
        .route("/proof/:transaction", get(proof::get_proof))
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
        State(client): State<LightClient>,
        Path(params): Path<Params>,
    ) -> impl IntoResponse {
        axum::Json(client.header(params.epoch).cloned())
    }

    pub(super) async fn get_head(State(client): State<LightClient>) -> impl IntoResponse {
        axum::Json(client.head().clone())
    }
}

mod proof {
    use axum::Json;
    use near_primitives_core::types::AccountId;

    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Params {
        transaction_id: CryptoHash,
        sender_id: AccountId,
    }

    pub(super) async fn get_proof(
        State(client): State<LightClient>,
        Path(params): Path<Params>,
    ) -> impl IntoResponse {
        axum::Json(
            client
                .get_proof(params.transaction_id, params.sender_id)
                .await,
        )
    }

    pub(super) async fn post_proof(
        State(client): State<LightClient>,
        Json(body): Json<Params>,
    ) -> impl IntoResponse {
        axum::Json(client.validate_proof(body))
    }
}

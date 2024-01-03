use crate::{client::LightClient, config::Config};
use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use coerce::actor::LocalActorRef;
use near_primitives_core::hash::CryptoHash;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

// TODO: replace with jsonrpc
pub(crate) fn init(config: &Config, ctx: LocalActorRef<LightClient>) -> JoinHandle<Result<()>> {
    let controller = Router::new()
        .route("/health", get(health_check))
        .route("/head", get(header::get_head))
        .with_state(ctx.clone())
        .route("/header/:epoch", get(header::get_by_epoch))
        .with_state(ctx.clone())
        .route("/proof", post(proof::post_get_proof))
        .with_state(ctx.clone())
        .route("/proof/verify", post(proof::post_verify_proof))
        .with_state(ctx.clone())
        .route("/proof/experimental", post(proof::post_get_batch_proof))
        .with_state(ctx.clone());

    let host = config.host.clone();
    tokio::spawn(async {
        let listener = tokio::net::TcpListener::bind(host).await.map_err(|e| {
            log::error!("Failed to start server: {:?}", e);
            anyhow::anyhow!(e)
        })?;
        println!("listening on {}", listener.local_addr().unwrap());
        axum::serve(listener, controller).await.map_err(|e| {
            log::error!("Failed to start server: {:?}", e);
            anyhow::anyhow!(e)
        })
    })
}

async fn health_check() -> StatusCode {
    StatusCode::OK
}

mod header {
    use super::*;
    use crate::client::message::{Archive, Head};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Params {
        epoch: CryptoHash,
    }

    pub(super) async fn get_by_epoch(
        State(client): State<LocalActorRef<LightClient>>,
        Path(params): Path<Params>,
    ) -> impl IntoResponse {
        client
            .send(Archive {
                epoch: params.epoch,
            })
            .await
            .map(axum::Json)
            .map_err(|_| internal_server_error())
    }

    pub(super) async fn get_head(
        State(client): State<LocalActorRef<LightClient>>,
    ) -> impl IntoResponse {
        client
            .send(Head)
            .await
            .map(axum::Json)
            .map_err(ErrorMapper)
            .map_err(IntoResponse::into_response)
    }
}

mod proof {
    use super::*;
    use crate::client::{
        message::{BatchGetProof, GetProof, VerifyProof},
        Proof,
    };
    use axum::Json;

    pub(super) async fn post_get_proof(
        State(client): State<LocalActorRef<LightClient>>,
        Json(params): Json<GetProof>,
    ) -> impl IntoResponse {
        client
            .send(params)
            .await
            .map(axum::Json)
            .map_err(ErrorMapper)
            .map_err(IntoResponse::into_response)
    }

    pub(super) async fn post_verify_proof(
        State(client): State<LocalActorRef<LightClient>>,
        Json(proof): Json<Proof>,
    ) -> impl IntoResponse {
        client
            .send(VerifyProof { proof })
            .await
            .map_err(|e| anyhow::anyhow!(e))
            .and_then(|x| x)
            .map(axum::Json)
            .map_err(ErrorMapper)
            .map_err(IntoResponse::into_response)
    }

    #[derive(Debug, Serialize)]
    pub struct BatchProofWithErrors {
        proofs: crate::client::protocol::experimental::Proof,
        errors: Vec<String>,
    }

    pub(super) async fn post_get_batch_proof(
        State(client): State<LocalActorRef<LightClient>>,
        Json(body): Json<BatchGetProof>,
    ) -> impl IntoResponse {
        client
            .send(body)
            .await
            .map_err(|e| anyhow::anyhow!(e))
            .and_then(|x| x.ok_or_else(|| anyhow::anyhow!("Failed to get batch proof")))
            .map_err(ErrorMapper)
            .map_err(IntoResponse::into_response)
            .map(|(proofs, errors)| BatchProofWithErrors {
                proofs,
                errors: errors.into_iter().map(|e| e.to_string()).collect(),
            })
            .map(axum::Json)
    }
}

struct ErrorMapper<T>(pub T);
impl<T> IntoResponse for ErrorMapper<T>
where
    T: ToString,
{
    fn into_response(self) -> Response {
        let mut r = Response::new(self.0.to_string().into());
        *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        r
    }
}

fn internal_server_error() -> impl IntoResponse {
    let mut r = Response::new("Error".to_string());
    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    r
}

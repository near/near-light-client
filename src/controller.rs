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
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::client::Message;

type ClientState = flume::Sender<Message>;

pub(crate) fn init(ctx: Sender<Message>) -> JoinHandle<Result<(), axum::Error>> {
    // TODO: probably only actually need one channel here, this queue system isn't great
    let (etx, erx) = flume::bounded(64);
    let (htx, hrx) = flume::bounded(64);
    let (pttx, ptrx) = flume::bounded(64);
    let (prtx, prrx) = flume::bounded(64);
    let (vptx, vprx) = flume::bounded(24);

    let controller = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/health", get(health_check))
        .route("/head", get(header::get_head))
        .with_state((ctx.clone(), htx, hrx))
        .route("/header/:epoch", get(header::get_by_epoch))
        .with_state((ctx.clone(), etx, erx))
        .route(
            "/proof/tx/:transaction_id/:sender_id",
            get(proof::get_tx_proof),
        )
        .with_state((ctx.clone(), pttx, ptrx))
        .route(
            "/proof/receipt/:receipt_id/:receiver_id",
            get(proof::get_receipt_proof),
        )
        .with_state((ctx.clone(), prtx, prrx))
        .route("/proof", post(proof::post_proof))
        .with_state((ctx.clone(), vptx, vprx));

    tokio::spawn(async {
        let r = axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .serve(controller.into_make_service())
            .await;
        r.map_err(|e| todo!("{:?}", e))
    })
}

#[derive(OpenApi)]
#[openapi(
    paths(
        health_check,
        header::get_head,
        header::get_by_epoch,
        proof::get_tx_proof,
        proof::get_receipt_proof,
        proof::post_proof,
    ),
    components(schemas(
        // header::LightClientBlockLiteView,
        // proof::Proof,
    )),
    tags((name = "Todo"))
)]
struct ApiDoc;

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Health is OK")
    ),
)]
async fn health_check() -> StatusCode {
    StatusCode::OK
}

mod header {
    use super::*;
    pub(super) use near_primitives::views::LightClientBlockLiteView;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Params {
        epoch: CryptoHash,
    }

    #[utoipa::path(
        get,
        path = "/header/:epoch",
        responses(
            (status = 200, description = "Get header for this epoch", body = LightClientBlockLiteView, content_type = "application/json"),
        ),
    )]
    pub(super) async fn get_by_epoch(
        State((client, tx, rx)): State<(
            ClientState,
            flume::Sender<Option<LightClientBlockLiteView>>,
            flume::Receiver<Option<LightClientBlockLiteView>>,
        )>,
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

    #[utoipa::path(
        get,
        path = "/head",
        responses(
            (status = 200, description = "Light client latest head", body = LightClientBlockLiteView, content_type = "application/json"),
        ),
    )]
    pub(super) async fn get_head(
        State((client, tx, rx)): State<(
            ClientState,
            flume::Sender<LightClientBlockLiteView>,
            flume::Receiver<LightClientBlockLiteView>,
        )>,
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
    pub(super) use crate::client::Proof;
    use crate::client::ProofType;
    use axum::Json;
    pub(super) use near_jsonrpc_client::methods::light_client_proof::RpcLightClientExecutionProofResponse;
    use near_primitives_core::types::AccountId;
    use utoipa::IntoParams;


    #[derive(Debug, Deserialize, Serialize, IntoParams)]
    pub struct TransactionParams {
        transaction_id: CryptoHash,
        sender_id: AccountId,
    }

    #[derive(Debug, Deserialize, Serialize, IntoParams)]
    pub struct ReceiptParams {
        receipt_id: CryptoHash,
        receiver_id: AccountId,
    }

    #[utoipa::path(
        post,
        path = "/proof/tx/:transaction_id/:sender_id",
        params(TransactionParams),
        responses(
            (status = 200, description = "Proof was created", body = Proof, content_type = "application/json"),
        ),
    )]
    pub(super) async fn get_tx_proof(
        State((client, tx, rx)): State<(
            ClientState,
            flume::Sender<Option<Proof>>,
            flume::Receiver<Option<Proof>>,
        )>,
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

    #[utoipa::path(
        post,
        path = "/proof/receipt/:receipt_id/:receiver_id",
        params(ReceiptParams),
        responses(
            (status = 200, description = "Proof was created", body = Proof, content_type = "application/json"),
        ),
    )]
    pub(super) async fn get_receipt_proof(
        State((client, tx, rx)): State<(
            ClientState,
            flume::Sender<Option<Proof>>,
            flume::Receiver<Option<Proof>>,
        )>,
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

    #[utoipa::path(
        post,
        path = "/proof",
        request_body(content = RpcLightClientExecutionProofResponse, content_type = "application/json"),
        responses(
            (status = 200, description = "Proof is valid", body = bool),
        ),
    )]
    pub(super) async fn post_proof(
        State((client, tx, rx)): State<(ClientState, flume::Sender<bool>, flume::Receiver<bool>)>,
        Json(proof): Json<RpcLightClientExecutionProofResponse>,
    ) -> impl IntoResponse {
        log::debug!("post_proof: {:?}", proof);
        if let Err(e) = client
            .send_async(Message::ValidateProof {
                tx,
                proof: Box::new(proof),
            })
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

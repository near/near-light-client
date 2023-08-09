use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use near_primitives_core::hash::CryptoHash;
use serde::{Deserialize, Serialize};

use crate::near::LightClient;

mod config;
mod near;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    // tracing_subscriber::fmt::init();

    let config = config::Config::new()?;

    // let (gtx, grx) = flume::bounded::<LightClientAction>(128);
    // let (ntx, nrx) = flume::bounded::<LightClientAction>(128);
    let (shutdown_tx, shutdown_rx) = flume::unbounded::<bool>();

    // Collect all the clients to shutdown
    // TODO: make this just take a list of sender Into<ShutdownMessage> or smth
    // then make every message implement it

    // let to_shutdown = vec![ntx.clone()];

    setup_exit_handler(shutdown_tx);

    // TODO extract to sync handler
    let mut client = LightClient::init(&config).await;
    while let Ok(true) = client.sync().await {
        log::info!("Syncing again");
    }

    let app = Router::new()
        .route("/header", get(by_epoch))
        .with_state(client.clone())
        .route("/header/:epoch", get(by_epoch))
        .with_state(client.clone());

    let webapi = tokio::spawn(
        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap()).serve(app.into_make_service()),
    );

    // This blocks until the shutdown signal is received
    shutdown_rx.recv_async().await;
    webapi.abort();
    // for tx in to_shutdown {
    //     // tx.send_async(LightClientAction::Shutdown).await;
    // }
    log::info!("Shutting down due to shutdown signal");

    Ok(())
}

async fn by_epoch(
    State(client): State<LightClient>,
    Path(params): Path<Params>,
) -> impl IntoResponse {
    let header = client.header(params.epoch);
    axum::Json(header.cloned())
}
async fn head(State(client): State<LightClient>, Path(params): Path<Params>) -> impl IntoResponse {
    axum::Json(client.head().clone())
}
#[derive(Debug, Deserialize, Serialize)]
struct Params {
    epoch: CryptoHash,
}

pub fn setup_exit_handler(shutdown_tx: flume::Sender<bool>) {
    tokio::spawn(async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            log::info!("Shutting down due to ctrlc");
            shutdown_tx.send_async(true).await.unwrap();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s() {}
}

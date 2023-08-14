use std::sync::Arc;

use client::Message;

use crate::client::LightClient;

mod client;
mod config;
mod controller;

pub struct ShutdownMsg;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    // tracing_subscriber::fmt::init();

    let config = config::Config::new()?;

    let (ctx, crx) = flume::bounded::<Message>(256);

    let (shutdown_tx, shutdown_rx) = flume::unbounded::<bool>();
    // Collect all the clients to shutdown
    // TODO: make this just take a list of sender Into<ShutdownMessage> or smth
    // let to_shutdown = vec![ntx.clone()];
    setup_exit_handler(shutdown_tx);

    LightClient::init(&config).await.start(true, crx);
    let webapi = controller::init(ctx.clone());

    // This blocks until the shutdown signal is received
    match shutdown_rx.recv_async().await {
        Err(e) => {
            log::error!("Error receiving shutdown signal: {}", e);
        }
        Ok(_) => {
            log::info!("Shutting down..");
            let _ = ctx
                .send_async(Message::Shutdown(config.debug, config.state_path))
                .await;
            webapi.abort();
        }
    };

    Ok(())
}

pub fn setup_exit_handler(shutdown_tx: flume::Sender<bool>) {
    tokio::spawn(async move {
        if let Ok(_) = tokio::signal::ctrl_c().await {
            log::info!("Shutting down due to ctrlc");
            let _ = shutdown_tx.send_async(true).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s() {}
}

use crate::near::LightClient;

mod config;
mod near;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    let config = config::Config::new()?;

    // let (gtx, grx) = flume::bounded::<LightClientAction>(128);
    // let (ntx, nrx) = flume::bounded::<LightClientAction>(128);
    let (shutdown_tx, shutdown_rx) = flume::unbounded::<bool>();

    // Collect all the clients to shutdown
    // TODO: make this just take a list of sender Into<ShutdownMessage> or smth
    // then make every message implement it

    // let to_shutdown = vec![ntx.clone()];

    setup_exit_handler(shutdown_tx);

    LightClient::init(&config).await;

    // This blocks until the shutdown signal is received
    shutdown_rx.recv_async().await;
    // for tx in to_shutdown {
    //     // tx.send_async(LightClientAction::Shutdown).await;
    // }
    log::info!("Shutting down due to shutdown signal");

    Ok(())
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

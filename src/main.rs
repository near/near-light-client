use crate::client::LightClient;
use client::Message;

mod client;
mod config;
mod controller;
mod erasure;

pub struct ShutdownMsg;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    // tracing_subscriber::fmt::init();

    let config = config::Config::new()?;

    let (ctx, crx) = flume::bounded::<Message>(256);

    LightClient::init(&config).await.start(true, crx);
    let webapi = controller::init(ctx.clone());

    if let Ok(_) = tokio::signal::ctrl_c().await {
        log::info!("Shutting down due to ctrlc");
        let _ = ctx.send(Message::Shutdown(config.debug, config.state_path));
        webapi.abort();
    }

    Ok(())
}

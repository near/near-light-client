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

    let config = config::Config::new()?;

    let (ctx, crx) = flume::bounded::<Message>(256);

    let lc = LightClient::init(&config).await?;
    lc.start(true, crx);
    let webapi = controller::init(ctx.clone());

    if tokio::signal::ctrl_c().await.is_ok() {
        log::info!("Shutting down due to ctrlc");
        let _ = ctx.send(Message::Shutdown(config.state_path));
        webapi.abort();
    }

    Ok(())
}

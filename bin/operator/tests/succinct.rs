use near_light_client_rpc::prelude::Itertools;
use nearx_operator::{config::Config, rpc::VERIFY_ID_AMT, succinct::*};
use test_utils::{fixture, testnet_state};

async fn client() -> Client {
    pretty_env_logger::try_init().ok();
    Client::new(&Config::test_config()).await.unwrap()
}

async fn test_sync() {
    let s = client().await.sync(false).await.unwrap();
    println!("synced with {:?}", s);
}

async fn test_sync_relay() {
    let s = client().await.sync(true).await.unwrap();
    println!("synced with {:?}", s);
}

async fn test_verify() {
    let client = client().await;

    let txs = fixture::<Vec<TransactionOrReceiptIdPrimitive>>("ids.json")
        .into_iter()
        .take(VERIFY_ID_AMT)
        .collect_vec();

    let s = client.verify(txs, false).await.unwrap();
    println!("verify with {:?}", s);
}

async fn test_verify_relay() {
    let client: Client = client().await;

    let txs = fixture::<Vec<TransactionOrReceiptIdPrimitive>>("ids.json")
        .into_iter()
        .take(VERIFY_ID_AMT)
        .collect_vec();

    let s = client.verify(txs, true).await.unwrap();
    println!("verify with {:?}", s);
}

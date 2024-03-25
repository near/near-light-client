#![allow(dead_code)] // Justification: Until we decide on test feature flags
use std::str::FromStr;

use near_light_client_rpc::prelude::Itertools;
use nearx_operator::{
    config::Config, succinct::*, types::TransactionOrReceiptIdPrimitive, BaseConfig,
};
use test_utils::fixture;
use uuid::Uuid;

async fn client() -> Client {
    pretty_env_logger::try_init().ok();
    Client::new(&Config::test_config()).await.unwrap()
}

// TODO: these test shouldn't be run in CI, probably sporadically
// #[tokio::test]
// async fn test_sync() {
//     let s = client().await.sync(false).await.unwrap();
//     println!("synced with {:?}", s);
// }
//
// #[tokio::test]
// async fn test_sync_relay() {
//     let s = client().await.sync(true).await.unwrap();
//     println!("synced with {:?}", s);
// }
//
// #[tokio::test]
// async fn test_verify() {
//     let client = client().await;
//
//     let txs = fixture::<Vec<TransactionOrReceiptIdPrimitive>>("ids.json")
//         .into_iter()
//         .take(VERIFY_AMT)
//         .collect_vec();
//
//     let s = client.verify(txs, false).await.unwrap();
//     println!("verify with {:?}", s);
// }
//
// #[tokio::test]
// async fn test_verify_relay() {
//     let client: Client = client().await;
//
//     let txs = fixture::<Vec<TransactionOrReceiptIdPrimitive>>("ids.json")
//         .into_iter()
//         .take(VERIFY_AMT)
//         .collect_vec();
//
//     let s = client.verify(txs, true).await.unwrap();
//     println!("verify with {:?}", s);
// }

#[tokio::test]
async fn test_check_proof() {
    let c = client().await;
    let request_id = "76688871-5262-4384-9891-0a68fe7a2efb";
    let p = c.wait_for_proof(&request_id).await.unwrap();
    println!("found proof: {:?}", p);
    assert_eq!(
        p.0,
        Uuid::from_str("3dcaeed9-b467-4d4f-bfb5-c22bac100527").unwrap()
    );
}

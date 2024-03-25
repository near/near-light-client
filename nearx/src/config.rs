use near_light_client_rpc::Network;

#[const_trait]
pub trait Config: std::fmt::Debug + Clone + PartialEq + Sync + Send + 'static {
    const NETWORK: Network;
    const BPS: usize;

    const VERIFY_AMT: usize;
    const VERIFY_BATCH: usize;
}

// TODO: Decide if we should always "bake in" the constants here at build time,
// since it requires a build to fix anyway. If the protocol config is changed
// then we would need to rebuild.
//
// We might also need additional measures to be able to handle this, likely we
// need to dynamically allocate the constants at runtime since verifying blocks
// in the past will not be valid for all protocol configurations.
//
// Maybe we just have 3 circuits, (fast, slow and very slow) and use them
// dynamically via the operator?
#[derive(Debug, Clone, PartialEq)]
pub struct Testnet;
impl const Config for Testnet {
    const NETWORK: Network = Network::Testnet;
    const BPS: usize = 20; // EXPERIMENTAL_protocol_config::num_block_producer_seats

    const VERIFY_AMT: usize = 64;
    const VERIFY_BATCH: usize = 4;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Mainnet;
impl const Config for Mainnet {
    const NETWORK: Network = Network::Mainnet;
    const BPS: usize = 100;

    const VERIFY_AMT: usize = 128;
    const VERIFY_BATCH: usize = 4;
}

#[derive(Debug, Clone, PartialEq)]
pub struct CustomBatchNumConfig<const A: usize = 2, const B: usize = 1>();
impl<const A: usize, const B: usize> const Config for CustomBatchNumConfig<{ A }, { B }> {
    const NETWORK: near_light_client_rpc::Network = Testnet::NETWORK;
    const BPS: usize = Testnet::BPS;
    const VERIFY_AMT: usize = A;
    const VERIFY_BATCH: usize = B;
}

pub fn bps_from_network(n: &near_light_client_rpc::Network) -> usize {
    match n {
        near_light_client_rpc::Network::Mainnet => Mainnet::BPS,
        near_light_client_rpc::Network::Testnet => Testnet::BPS,
        _ => todo!("Unsupported"),
    }
}

cfg_if::cfg_if! {
    if #[cfg(test)] {
        #[derive(Debug, Clone, PartialEq)]
        pub struct FixturesConfig<T: Config = Testnet, const B: usize = 50>(std::marker::PhantomData<T>);
        impl<T: Config, const B: usize> const Config for FixturesConfig<T, { B }> {
            const NETWORK: Network = T::NETWORK;
            const BPS: usize = B;
            const VERIFY_AMT: usize = T::VERIFY_AMT;
            const VERIFY_BATCH: usize = T::VERIFY_BATCH;
        }
    }
}

#[cfg(test)]
mod tests {
    use near_light_client_rpc::{LightClientRpc, NearRpcClient};

    use super::*;

    async fn check_config<Config: super::Config>() {
        let client = NearRpcClient::new(&(Config::NETWORK.into()));
        let to_check = near_light_client_rpc::BlockReference::latest();

        let config = client.fetch_protocol_config(&to_check).await.unwrap();
        assert_eq!(
            config.num_block_producer_seats as usize,
            Config::BPS,
            "BPS mismatch with circuit config, update the config!"
        );
    }

    #[tokio::test]
    async fn test_verify_testnet_config() {
        check_config::<Testnet>().await
    }

    #[tokio::test]
    async fn test_verify_mainnet_config() {
        check_config::<Mainnet>().await
    }
}

use near_light_client_rpc::Network;

#[const_trait]
pub trait Config: std::fmt::Debug + Clone + PartialEq + Sync + Send + 'static {
    const NETWORK: Network;
    const BPS: usize;

    const VERIFY_AMT: usize;
    const VERIFY_BATCH: usize;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Testnet;
impl const Config for Testnet {
    const NETWORK: Network = Network::Testnet;
    const BPS: usize = 50; // In practice we only see 30-35

    const VERIFY_AMT: usize = 64;
    const VERIFY_BATCH: usize = 4;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Mainnet;
impl const Config for Mainnet {
    const NETWORK: Network = Network::Mainnet;
    const BPS: usize = 50;

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

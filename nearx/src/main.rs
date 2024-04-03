#![allow(unused_imports)]
use near_light_clientx::{
    config::{Config, Mainnet, Testnet},
    plonky2x::backend::function::Plonky2xFunction,
};

fn main() {
    #[allow(dead_code)]
    type Conf = Testnet;

    cfg_if::cfg_if! {
        if #[cfg(feature = "sync")] {
            use near_light_clientx::SyncCircuit;
            SyncCircuit::<Conf>::entrypoint();
        } else if #[cfg(feature = "verify")] {

            assert!(Conf::VERIFY_AMT % Conf::VERIFY_BATCH == 0);
            assert!((Conf::VERIFY_AMT / Conf::VERIFY_BATCH).is_power_of_two());

            use near_light_clientx::VerifyCircuit;
            VerifyCircuit::<CFG>::entrypoint();
        } else {
            panic!("No circuit feature enabled");
        }
    }
}

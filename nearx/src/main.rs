#![allow(unused_imports)]
use near_light_clientx::{
    config::{Config, Mainnet, Testnet},
    plonky2x::backend::function::Plonky2xFunction,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "testnet")] {
        type CFG = Testnet;
    } else if #[cfg(feature = "mainnet")] {
        type CFG = Mainnet;
    } else {
        panic!("No network feature enabled")
    }
}

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(feature = "sync")] {
            use near_light_clientx::SyncCircuit;
            SyncCircuit::<CFG>::entrypoint();
        } else if #[cfg(feature = "verify")] {

            assert!(CFG::VERIFY_AMT % CFG::VERIFY_BATCH == 0);
            assert!((CFG::VERIFY_AMT / CFG::VERIFY_BATCH).is_power_of_two());

            use near_light_clientx::VerifyCircuit;
            VerifyCircuit::<CFG>::entrypoint();
        } else {
            panic!("No circuit feature enabled");
        }
    }
}

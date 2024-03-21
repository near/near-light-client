#[allow(unused_imports)]
use near_light_clientx::{plonky2x::backend::function::Plonky2xFunction, VERIFY_AMT, VERIFY_BATCH};

// Testnet, FIXME: this is error prone, use something else
#[allow(dead_code)]
const NETWORK: usize = 1;

// TODO: make this use a nicer API for use by the prover.
// TODO: perpetually sync, use queue etc
fn main() {
    cfg_if::cfg_if! {
        if #[cfg(feature = "sync")] {
            use near_light_clientx::SyncCircuit;
            SyncCircuit::<NETWORK>::entrypoint();
        } else if #[cfg(feature = "verify")] {

            assert!(VERIFY_AMT % VERIFY_BATCH == 0);
            assert!((VERIFY_AMT / VERIFY_BATCH).is_power_of_two());

            use near_light_clientx::VerifyCircuit;
            VerifyCircuit::<VERIFY_AMT, VERIFY_BATCH, NETWORK>::entrypoint();
        } else {
            panic!("No circuit feature enabled");
        }
    }
}

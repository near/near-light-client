use near_light_clientx::{Circuits, Plonky2xFunction};

// Testnet, FIXME: this is error prone, use something else
#[allow(dead_code)]
const NETWORK: usize = 1;

// TODO: make this use a nicer API for use by the prover.
// TODO: perpetually sync, use queue etc
fn main() {
    Circuits::<NETWORK>::entrypoint();
    cfg_if::cfg_if! {
        if #[cfg(feature = "sync")] {
            use near_light_clientx::SyncCircuit;
            SyncCircuit::<NETWORK>::entrypoint();
        } else if #[cfg(feature = "verify")] {
            const PROOF_AMT: usize = 64;
            const PROOF_BATCH_SIZE: usize = 4;

            assert!(PROOF_AMT % PROOF_BATCH_SIZE == 0);
            assert!((PROOF_AMT / PROOF_BATCH_SIZE).is_power_of_two());

            use near_light_clientx::VerifyCircuit;
            VerifyCircuit::<PROOF_AMT, PROOF_BATCH_SIZE, NETWORK>::entrypoint();
        } else {
            panic!("No circuit feature enabled");
        }
    }
}

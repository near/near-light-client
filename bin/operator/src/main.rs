use near_light_clientx::plonky2x::backend::function::Plonky2xFunction;

// Testnet, FIXME: this is error prone, use something else
const NETWORK: usize = 1;

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(feature = "sync")] {
            use near_light_clientx::SyncCircuit;
            SyncCircuit::<NETWORK>::entrypoint();
        } else if #[cfg(feature = "verify")] {
            const PROOF_AMT: usize = 64;
            const PROOF_BATCH_SIZE: usize = 8;
            use near_light_clientx::VerifyCircuit;
            VerifyCircuit::<PROOF_AMT, PROOF_BATCH_SIZE, NETWORK>::entrypoint();
        } else {
            panic!("No circuit feature enabled");
        }
    }
}

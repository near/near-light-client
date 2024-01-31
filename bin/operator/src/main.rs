use near_light_clientx::{plonky2x::backend::function::Plonky2xFunction, SyncCircuit};

fn main() {
    cfg_if::cfg_if! {
        if #[cfg(feature = "sync")] {
            SyncCircuit::entrypoint();
        } else {
            panic!("No circuit feature enabled");
        }
    }
}

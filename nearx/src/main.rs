#[cfg(any(feature = "sync", feature = "verify"))]
use near_light_clientx::plonky2x::backend::function::Plonky2xFunction;

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
            const PROOF_AMT: usize = 128;
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

#[cfg(test)]
mod tests {
    use succinct_client::request::{Address, Bytes, SuccinctClient};
    use test_utils::workspace_dir;

    use super::*;

    #[tokio::test]
    async fn test_local_prove() {
        pretty_env_logger::try_init().unwrap_or_default();

        let workspace_dir = &workspace_dir();
        let workspace_dir = workspace_dir.display();
        let client = SuccinctClient::new(
            "https://alpha.succinct.xyz/api".to_string(),
            "".to_string(),
            true,
            true,
        );
        let result = client
            .submit_request(
                5,
                Address::default(),
                Bytes::default(),
                [0u8; 32].into(),
                vec![].into(),
            )
            .await
            .unwrap();
        std::env::set_var(
            "PROVE_BINARY_0x0000000000000000000000000000000000000000000000000000000000000000",
            "sync",
        );
        println!("{result}");
        // SuccinctClient::run_local_prover_docker_image(
        //     "../verifier-build/verifier",
        //     "../build",
        //     "sync",
        //     "input.json",
        // );
    }
}

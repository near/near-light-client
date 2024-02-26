use std::fs;
pub use std::str::FromStr;

pub use near_primitives::hash::CryptoHash;
use plonky2x::backend::function::{BytesRequestData, ProofRequest};
pub use plonky2x::{
    backend::circuit::{PublicInput, PublicOutput},
    prelude::*,
};
pub use test_utils::*;

// Testnet Repr
pub const NETWORK: usize = 1;

pub type B<const D: usize = 2> = CircuitBuilder<DefaultParameters, D>;
pub type PI<const D: usize = 2> = PublicInput<DefaultParameters, D>;
pub type PO<const D: usize = 2> = PublicOutput<DefaultParameters, D>;

pub fn builder_suite<F, WriteInputs, Assertions>(
    define: F,
    writer: WriteInputs,
    assertions: Assertions,
) where
    F: FnOnce(&mut B),
    WriteInputs: FnOnce(&mut PI),
    Assertions: FnOnce(PO),
{
    logger();
    let mut builder = B::new();
    define(&mut builder);

    let circuit = builder.build();

    let mut inputs = circuit.input();
    writer(&mut inputs);

    let proof_req = match &inputs {
        PublicInput::Bytes(bytes) => Some(ProofRequest::<DefaultParameters, 2>::Bytes(
            plonky2x::backend::function::ProofRequestBase {
                release_id: "todo".to_string(),
                parent_id: None,
                files: None,
                data: BytesRequestData {
                    input: bytes.clone(),
                },
            },
        )),
        PublicInput::Elements(elements) => Some(ProofRequest::<DefaultParameters, 2>::Elements(
            plonky2x::backend::function::ProofRequestBase {
                release_id: "todo".to_string(),
                parent_id: None,
                files: None,
                data: plonky2x::backend::function::ElementsRequestData {
                    circuit_id: "todo".to_string(),
                    input: elements.clone(),
                },
            },
        )),
        _ => None,
    };
    if let Some(req) = proof_req {
        fs::write("../build/input.json", serde_json::to_string(&req).unwrap()).unwrap();
    }

    let (proof, output) = circuit.prove(&inputs);

    assertions(output.clone());

    circuit.verify(&proof, &inputs, &output);
}

#[allow(dead_code)]
pub fn mock_builder_suite<F, WriteInputs, Assertions>(
    define: F,
    writer: WriteInputs,
    assertions: Assertions,
) where
    F: FnOnce(&mut B),
    WriteInputs: FnOnce(&mut PI),
    Assertions: FnOnce(PO),
{
    pretty_env_logger::try_init().unwrap_or_default();

    let mut builder = B::new();
    define(&mut builder);

    let circuit = builder.mock_build();

    let mut inputs = circuit.input();
    writer(&mut inputs);

    let (witness, output) = circuit.mock_prove(&inputs);
    println!("Mock proof {:#?}", witness.full_witness());

    assertions(output.clone());
}

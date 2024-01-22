pub use crate::variables::*;
pub use near_light_client_protocol::{
    prelude::{BasicProof, Header, Itertools},
    LightClientBlockView, Protocol, StakeInfo, ValidatorStake,
};
pub use near_primitives::hash::CryptoHash;
pub use plonky2x::backend::circuit::{PublicInput, PublicOutput};
pub use plonky2x::prelude::*;
pub use pretty_assertions::assert_eq;
pub use serde::de::DeserializeOwned;
pub use std::str::FromStr;

pub type B<const D: usize = 2> = CircuitBuilder<DefaultParameters, D>;
pub type PI<const D: usize = 2> = PublicInput<DefaultParameters, D>;
pub type PO<const D: usize = 2> = PublicOutput<DefaultParameters, D>;

pub fn fixture<T: DeserializeOwned>(file: &str) -> T {
    serde_json::from_reader(std::fs::File::open(format!("../../fixtures/{}", file)).unwrap())
        .unwrap()
}

pub fn get_next_epoch() -> LightClientBlockView {
    fixture("2.json")
}

pub fn get_first_epoch() -> LightClientBlockView {
    fixture("1.json")
}

pub fn view_to_lite_view(h: LightClientBlockView) -> Header {
    Header {
        prev_block_hash: h.prev_block_hash,
        inner_rest_hash: h.inner_rest_hash,
        inner_lite: h.inner_lite,
    }
}

pub fn test_state() -> (Header, Vec<ValidatorStake>, LightClientBlockView) {
    let first = get_first_epoch();
    let next = get_next_epoch();

    (
        view_to_lite_view(first.clone()),
        first
            .next_bps
            .clone()
            .unwrap()
            .into_iter()
            .map(Into::into)
            .collect(),
        next,
    )
}

pub fn to_header(bv: LightClientBlockView) -> Header {
    Header {
        prev_block_hash: bv.prev_block_hash,
        inner_rest_hash: bv.inner_rest_hash,
        inner_lite: bv.inner_lite,
    }
}

pub fn builder_suite<F, WriteInputs, Assertions>(
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

    let circuit = builder.build();

    let mut inputs = circuit.input();
    writer(&mut inputs);

    let (proof, output) = circuit.prove(&inputs);

    assertions(output.clone());

    circuit.verify(&proof, &inputs, &output);
}

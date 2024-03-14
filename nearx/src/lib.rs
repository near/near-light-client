use std::fmt::format;

use clap::{Parser, Subcommand, ValueEnum};
pub use plonky2x::{
    self,
    backend::{circuit::Circuit, function::Plonky2xFunction},
    prelude::*,
};
use plonky2x::{
    backend::{
        circuit::Groth16WrapperParameters,
        function::{
            args::{BuildArgs, ProveArgs},
            ProofRequest,
        },
    },
    prelude::plonky2::plonk::config::{AlgebraicHasher, GenericConfig},
};
use serde::Serialize;
pub use sync::SyncCircuit;
pub use verify::VerifyCircuit;

/// Building blocks injected into the CircuitBuilder
mod builder;
mod hint;
/// Unprefixed merkle tree without collision resistance
mod merkle;
mod variables;

/// Circuits for use by the operator
pub mod sync;
pub mod verify;

#[cfg(test)]
mod test_utils;

#[derive(ValueEnum, Debug, Clone)]
pub enum Selector {
    Sync,
    Verify2,
    Verify16,
}

impl Selector {
    pub const fn verify_amt(&self) -> usize {
        match self {
            Selector::Sync => todo!(),
            Selector::Verify2 => 2,
            Selector::Verify16 => 16,
        }
    }
    pub const fn verify_batch(&self) -> usize {
        match self {
            Selector::Sync => todo!(),
            Selector::Verify2 => 1,
            Selector::Verify16 => 4,
        }
    }
    pub const fn prefix(&self) -> &'static str {
        match self {
            Selector::Sync => "sync",
            Selector::Verify2 => "verify_2",
            Selector::Verify16 => "verify_16",
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct SelectableProveArgs {
    #[arg(long)]
    circuit: Selector,

    #[command(flatten)]
    args: ProveArgs,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    Build(BuildArgs),
    Prove(SelectableProveArgs),
}

#[derive(Parser, Debug, Clone)]
#[command(about = "A tool for building and proving NEARX circuits.")]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

pub struct Circuits<const N: usize> {
    pub sync_circuit: crate::SyncCircuit<N>,
}

impl<const N: usize> Plonky2xFunction for Circuits<N> {
    fn entrypoint() {
        type L = DefaultParameters;
        type W = Groth16WrapperParameters;
        const D: usize = 2;

        let args = Args::parse();
        match args.command {
            Commands::Build(args) => {
                Self::build::<L, Groth16WrapperParameters, D>(args);
            }
            Commands::Prove(mut args) => {
                let prefix = args.circuit.prefix();
                let prefixed = |file: &String| format!("{prefix}/{}", file);

                match args.circuit {
                    Selector::Sync => {
                        let request = ProofRequest::<L, D>::load(&prefixed(&args.args.input_json));
                        SyncCircuit::<N>::prove::<_, W, D>(args.args, request);
                    }
                    Selector::Verify16 => {
                        let request = ProofRequest::<L, D>::load(&prefixed(&args.args.input_json));
                        VerifyCircuit::<16, 4>::prove::<_, W, D>(args.args, request);
                    }
                    Selector::Verify2 => {
                        let request = ProofRequest::<L, D>::load(&prefixed(&args.args.input_json));
                        VerifyCircuit::<2, 1>::prove::<_, W, D>(args.args, request);
                    }
                }
            }
        }
    }
    fn build<
        L: PlonkParameters<D>,
        WrapperParameters: PlonkParameters<D, Field = L::Field>,
        const D: usize,
    >(
        args: BuildArgs,
    ) where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        let mut specific_args = args.clone();
        specific_args.build_dir = format!("{}/sync", args.build_dir);
        <SyncCircuit<N> as Plonky2xFunction>::build::<L, WrapperParameters, D>(
            specific_args.clone(),
        );

        specific_args.build_dir = format!("{}/verify_large", args.build_dir);
        <VerifyCircuit<64, 4, N> as Plonky2xFunction>::build::<L, WrapperParameters, D>(
            specific_args.clone(),
        );

        specific_args.build_dir = format!("{}/verify", args.build_dir);
        <VerifyCircuit<16, 4, N> as Plonky2xFunction>::build::<L, WrapperParameters, D>(
            specific_args.clone(),
        );

        specific_args.build_dir = format!("{}/verify_small", args.build_dir);
        <VerifyCircuit<2, 1, N> as Plonky2xFunction>::build::<L, WrapperParameters, D>(
            specific_args.clone(),
        );
    }

    fn prove<
        InnerParameters: PlonkParameters<D>,
        OuterParameters: PlonkParameters<D, Field = InnerParameters::Field>,
        const D: usize,
    >(
        args: ProveArgs,
        request: ProofRequest<InnerParameters, D>,
    ) where
        <InnerParameters::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<InnerParameters::Field>,
        OuterParameters::Config: Serialize,
    {
        // first argument is selector, then pass rest to circuit
        todo!()
    }

    fn verifier(circuit_digest: &str, wrapper_path: &str) -> String {
        todo!()
    }
}

pub use plonky2x::{self, backend::circuit::Circuit, prelude::*};
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

pub const VERIFY_AMT: usize = 64;
pub const VERIFY_BATCH: usize = 4;

#[cfg(test)]
mod beefy_tests {
    use log::logger;
    use serial_test::serial;

    use super::*;
    use crate::test_utils::NETWORK;

    #[test]
    #[serial]
    #[ignore]
    fn sync_serialization() {
        logger();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        SyncCircuit::<NETWORK>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        SyncCircuit::<NETWORK>::register_generators(&mut hint_registry);
        SyncCircuit::<NETWORK>::register_gates(&mut gate_registry);

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    #[test]
    #[serial]
    #[ignore]
    fn verify_serialization() {
        logger();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        VerifyCircuit::<VERIFY_AMT, VERIFY_BATCH, NETWORK>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        VerifyCircuit::<VERIFY_AMT, VERIFY_BATCH, NETWORK>::register_generators(&mut hint_registry);
        VerifyCircuit::<VERIFY_AMT, VERIFY_BATCH, NETWORK>::register_gates(&mut gate_registry);

        circuit.test_serializers(&gate_registry, &hint_registry);
    }
}

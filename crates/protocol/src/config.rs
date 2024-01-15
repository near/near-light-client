use near_primitives_core::types::NumSeats;

// https://github.com/near/nearcore/blob/master/nearcore/src/config.rs#L133C1-L134C1
// TODO: expose this from NP, currently this is a risk that the light client could be exploited
// if the max seats changes without knowing
pub const NUM_BLOCK_PRODUCER_SEATS: usize = 50;

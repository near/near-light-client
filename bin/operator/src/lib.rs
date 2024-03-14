pub use prelude::*;

pub mod config;
pub mod queue;
pub mod rpc;
pub mod succinct;

pub mod prelude {
    pub use actix::{self, prelude::*};
    pub use near_light_client_primitives::prelude::*;

    pub use crate::{
        config::Config,
        queue::QueueManager,
        rpc::{ProveRpcServer as RpcServerExt, RpcServerImpl as RpcServer},
        succinct::{Client as SuccinctClient, *},
    };
}
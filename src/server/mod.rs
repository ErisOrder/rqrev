use tokio::net::TcpStream;
use tracing::{debug, error, info, trace, warn};

mod connection;
mod handler;
mod cli;
mod state;
mod locshard;
mod db;

mod prelude {
    pub use crate::rqode_binrw::*;
    pub use crate::protocol::*;
    pub use crate::server::state::*;
    pub use crate::server::db::model as db;

    pub use tracing::{error, warn, info, debug, trace};
    
    pub use anyhow::{Result, bail};
    pub use std::sync::Arc;
}

use prelude::*;

use crate::server::locshard::ShardState;

pub struct Server {
    state: Arc<State>,
}

impl Server {
    pub fn init() -> Self {
        let state = Arc::new(State::new());

        // Start locations/shards
        for loc in [25565] {
            let mut ss = ShardState::new(loc, state.clone());
            info!("Starting location {loc}");
            std::thread::spawn(move || ss.run());
        }

        Self {
            state 
        }
    }
    
    pub fn add_connection(&self, stream: TcpStream) {
        tokio::spawn(connection::connection_proc(self.state.clone(), stream));
    }
}



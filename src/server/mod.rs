use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::{debug, error, info, trace, warn};

mod connection;
mod handler;
mod cli;

pub struct Server {
    state: Arc<State>,
}

impl Server {
    pub fn init() -> Self {
        Self {
            state: Arc::new(State {})
        }
    }
    
    pub fn add_connection(&self, stream: TcpStream) {
        tokio::spawn(connection::connection_proc(self.state.clone(), stream));
    }
}

pub struct State {
    
}


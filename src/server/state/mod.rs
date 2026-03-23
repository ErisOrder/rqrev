use std::{collections::HashMap, time::Instant};

use anyhow::{Result, bail};
use parking_lot::RwLock;

use crate::server::{db::{Database, MockDatabase, model::CharacterBundle}, locshard::{MobBundle, PlayerBundle, Position}};

mod datamap;
mod login;

pub enum EntityBundle {
    Player(PlayerBundle),
    Mob(MobBundle),
}

pub struct MessageFromShard {
    pub shard_id: u32,
    pub kind: MessageFromShardKind,
}

pub enum MessageFromShardKind {
    EntityMove {
        id: u32,
        pos: glam::Vec2,
    },
    EntitySpawn {
        bundle: EntityBundle,
    },
    PlayerLoaded {
        bundle: PlayerBundle,
    }
}

pub enum MessageForShard {
    PlayerEnter {
        id: u32,
    },
    PlayerMove {
        id: u32,
        pos: glam::Vec2,
    },
    MobSpawn {
        player_id: u32,
        level: u16,
        mob_id: u16,
        hp: u32,
    }
}

pub struct State {
    /// Player senders
    pub player_tx: RwLock<HashMap<u32, flume::Sender<MessageFromShard>>>,
    /// Player receivers
    pub player_rx: RwLock<HashMap<u32, flume::Receiver<MessageFromShard>>>,

    /// Shard senders, identified by location id
    pub shard_tx: RwLock<HashMap<u32, flume::Sender<MessageForShard>>>,

    /// In-memory character data
    pub chardata: RwLock<HashMap<u32, CharacterBundle>>,

    pub sessions: RwLock<HashMap<u64, String>>,

    pub db: Box<dyn Database + Send + Sync>,
    
    pub starttime: Instant,
}

impl State {
    pub fn new() -> Self {
        Self {
            player_tx: Default::default(),
            player_rx: Default::default(),

            shard_tx: Default::default(),

            chardata: Default::default(),
            sessions: Default::default(),

            db: Box::new(MockDatabase),
            
            starttime: Instant::now(),
        }
    }
    
    pub fn timestamp(&self) -> u64 {
        chrono::Utc::now().timestamp_millis() as u64
    }

    pub fn uptime(&self) -> u32 {
        self.starttime.elapsed().as_millis() as u32
    }

    pub async fn load_char_from_db(&self, id: u32) -> Result<()> {
        let Some(bundle) = self.db.read_character(id).await? else {
            bail!("no such character")
        };
        
        self.chardata.write().insert(id, bundle);
        Ok(())
    }

    
}

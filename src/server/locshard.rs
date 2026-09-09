
use std::sync::Arc;

use bevy_ecs::{prelude::*, query::Spawned};
use glam::Vec2;

use crate::{rqode_binrw::BodyParam, server::{db::model::CharacterBundle, state::{EntityBundle, MessageForShard, MessageFromShard, MessageFromShardKind, State}}};

#[derive(Component, derive_more::Deref, derive_more::DerefMut, Clone, Copy, derive_more::From, Debug)]
pub struct Position(pub Vec2);

#[derive(Component, Clone, Debug)]
pub struct Mob {
    pub id: u16,
}
#[derive(Component, Clone, Debug, Default)]
pub struct Vector {
    pub x: f32,
    pub y: f32,
    pub rot: f32,
}
#[derive(Component, Clone, Debug)]
pub struct Health {
    pub value: u32,
    pub max: u32,
}
#[derive(Component, Clone, Debug)]
pub struct Energy {
    pub value: u32,
    pub max: u32,
}
#[derive(Component, Clone, Debug)]
pub struct Player {
    pub body: BodyParam,
    pub sex: bool,
    pub class: u16,
}
#[derive(Component, Clone, Debug)]
pub struct Id(pub u32);
#[derive(Component, Clone, Debug)]
pub struct Name {
    pub name: String,
}
#[derive(Component, Clone, Debug)]
pub struct Level {
    pub level: u16,
}

#[derive(Bundle, Clone, Debug)]
pub struct PlayerBundle {
    pub player: Player,
    pub id: Id,
    pub name: Name,
    pub pos: Position,
    pub vel: Vector,
    pub health: Health,
    pub energy: Energy,
    pub level: Level,
}


#[derive(Bundle, Clone, Debug)]
pub struct MobBundle {
    pub mob: Mob,
    pub id: Id,
    pub pos: Position,
    pub vel: Vector,
    pub health: Health,
    pub level: Level,
}

pub struct ShardState {
    pub sch: Schedule,
    pub world: World,
    pub rx: flume::Receiver<MessageForShard>,
    pub state: Arc<State>,
}

#[derive(Resource, derive_more::Deref)]
pub struct ServerState(Arc<State>);

#[derive(Resource)]
pub struct Location {
    id: u32,
}

impl ShardState {
    pub fn new(
        location: u32,
        state: Arc<State>,
    ) -> Self {
        let mut world = World::new();

        // Create channel for shard
        let (tx, rx) = flume::unbounded();
        state.shard_tx.write().insert(location, tx);

        world.insert_resource(ServerState(state.clone()));
        world.insert_resource(Location { id: location, });
        
        world.add_observer(on_player_move);

        let mut sch = Schedule::default();
        
        sch.add_systems(player_spawn);
        sch.add_systems(entity_move);
        
        Self {
            sch,
            world,
            state,
            rx,
        }
    }

    /// Shard loop
    pub fn run(&mut self) -> ! {
        
        loop {
            // Process messages
            while let Ok(msg) = self.rx.try_recv() {
                self.on_msg(msg);
            }

            // Run world
            self.sch.run(&mut self.world);
        }
    } 

    fn on_msg(&mut self, msg: MessageForShard) {
        match msg {
            MessageForShard::PlayerEnter { id } => {
                if let Some(bundle) = self.state.chardata.read().get(&id).cloned() {
                    self.world.spawn(PlayerBundle::from(bundle));
                } 
            },
            MessageForShard::PlayerMove { id, pos } => {
                let ev = PlayerMoveEvent {
                    player_id: id,
                    pos: Position(pos),
                };

                self.world.trigger(ev);
            },
            MessageForShard::MobSpawn { player_id, level, mob_id, hp } => {
                let ev = MobSpawnRequest {
                    player_id,
                    level,
                    mob_id,
                    hp,
                };

                self.world.trigger(ev);
            }
        }
    }
}

#[derive(Event)]
struct PlayerMoveEvent {
    player_id: u32,
    pos: Position,
}

/// Player moved
fn on_player_move(
    ev: On<PlayerMoveEvent>,
    q: Query<(&mut Position, &Id)>
) {
    for (mut pos, id) in q {
        if id.0 == ev.player_id {
            *pos = ev.pos;
        }
    }
}

#[derive(Event)]
struct MobSpawnRequest {
    player_id: u32,
    level: u16,
    mob_id: u16,
    hp: u32,
}

// fn on_mob_spawn_req(ev: On<MobSpawnRequest>, q: Query<&Position, >) {
    
// }

/// Send EntitySpawn notifications to other players
///
/// And init for this player
fn player_spawn(
    s: Res<ServerState>,
    loc: Res<Location>,
    spawned: Query<(Entity, &Player, &Id, &Position), Spawned>,
    players: Query<(&Id, &Position), With<Player>>,
    entities: Query<(Entity, &Id, &Position)>,
    w: &World,
) {
    for (ent, player, id, pos) in spawned {
        let Some(tx) = s.player_tx.read().get(&id.0).cloned() else {
            continue;
        };
        
        // Send player data for spawned players
        let ent = w.entity(ent);
        tx.send(MessageFromShard {
            shard_id: loc.id,
            kind: MessageFromShardKind::PlayerLoaded { bundle: PlayerBundle {
                player: player.clone(),
                id: id.clone(),
                name: ent.get().cloned().unwrap(),
                pos: pos.clone(),
                vel: Vector::default(),
                health: ent.get().cloned().unwrap(),
                energy: ent.get().cloned().unwrap(),
                level: ent.get().cloned().unwrap(),
            } }
        }).ok();

        // Send existing entities for spawned players
        for (ent, eid, pos) in entities {
            // Except self
            if eid.0 == id.0 {
                continue;
            }
            
            let ent = w.entity(ent);
            
            if ent.contains::<Player>() {               
                tx.send(MessageFromShard {
                    shard_id: loc.id,
                    kind: MessageFromShardKind::EntitySpawn {
                        bundle: EntityBundle::Player(PlayerBundle {
                            player: ent.get().cloned().unwrap(),
                            id: eid.clone(),
                            name: ent.get().cloned().unwrap(),
                            pos: pos.clone(),
                            vel: Vector::default(),
                            health: ent.get().cloned().unwrap(),
                            energy: ent.get().cloned().unwrap(),
                            level: ent.get().cloned().unwrap(),
                    })
                }}).ok();
            }
        }
    }
    
    // Send new player data to existing players
    for (id, pos) in players {
        if let Some(tx) = s.player_tx.read().get(&id.0) {
            for (ent, player, eid, pos) in spawned {
                if id.0 == eid.0 {
                    continue;
                }
                
                let ent = w.entity(ent);
                tx.send(MessageFromShard {
                    shard_id: loc.id,
                    kind: MessageFromShardKind::EntitySpawn {
                        bundle: EntityBundle::Player(PlayerBundle {
                            player: player.clone(),
                            id: eid.clone(),
                            name: ent.get().cloned().unwrap(),
                            pos: pos.clone(),
                            vel: Vector::default(),
                            health: ent.get().cloned().unwrap(),
                            energy: ent.get().cloned().unwrap(),
                            level: ent.get().cloned().unwrap(),
                    })
                }}).ok();
            }
        }
    }
}

/// Any entity moved
fn entity_move(
    s: Res<ServerState>,
    loc: Res<Location>,
    q: Query<(&Id, &Position), Changed<Position>>,
    players: Query<(&Id, &Position), With<Player>>
) {
    for (id, pos) in players {
        if let Some(tx) = s.player_tx.read().get(&id.0) {
            for (eid, pos) in q {
                // Skip self
                if eid.0 == id.0 {
                    continue;
                }
                
                // TODO: Join to single packet
                tx.send(MessageFromShard {
                    shard_id: loc.id,
                    kind: MessageFromShardKind::EntityMove {
                        id: eid.0,
                        pos: pos.0.into(),
                    }
                }).ok();
            }
        }
    }
}

impl From<CharacterBundle> for PlayerBundle {
    fn from(value: CharacterBundle) -> Self {
        PlayerBundle {
            player: Player {
                body: value.char.body,
                sex: value.char.sex,
                class: value.char.class,
            },
            id: Id(value.char.id),
            name: Name { name: value.char.name },
            pos: Position(value.char.pos),

            vel: Vector { x: 0.0, y: 0.0, rot: 0.0 },
            health: Health { value: value.stats.current_hp, max: value.stats.max_hp },
            energy: Energy { value: value.stats.current_energy, max: value.stats.max_energy },
            level: Level { level: value.char.level },
        }
    }
}

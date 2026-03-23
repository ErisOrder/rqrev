
use std::time::Duration;

use binrw::BinRead;

use crate::server::connection::ConnectionInfo;

use crate::server::prelude::*;

impl State {
    pub fn send_packet_to_shard(
        &self,
        info: &mut ConnectionInfo,
        packet: Packet,
    ) -> Result<()> {
        let Some(shard) = info.shard_id else {
            bail!("noi shard id")
        };

        let Some(tx) = self.shard_tx.read().get(&shard).cloned() else {
            bail!("no such shard")
        };

        let Some(charid) = info.character_id else {
            bail!("no char id")
        };
        
        match packet {
            // Packet::SendChatMessage(send_chat_message) => todo!(),
            Packet::CharacterMove(p) => {
                tx.send(MessageForShard::PlayerMove {
                    id: charid,
                    pos: p.coords.into()
                })?;
            },
            // Packet::UseAbility(p) => todo!(),
            // Packet::PickupRequest(p) => todo!(),
            // Packet::MoveItemRequest(p) => todo!(),
            // Packet::StatUpdateRequest(p) => todo!(),
            // Packet::BuyItemRequest(p) => todo!(),
            // Packet::SellItemRequest(p) => todo!(),
            // Packet::BuyBackRequest(p) => todo!(),
            // Packet::ShowEmotion(p) => todo!(),
            _ => {
                error!("unexpected client packet");
            }
        }

        Ok(())
    }

    pub fn send_msg_to_shard(
        &self,
        info: &mut ConnectionInfo,
        shard_id: u32,
        msg: MessageForShard,
    ) -> Result<()> {
        let Some(tx) = self.shard_tx.read().get(&shard_id).cloned() else {
            bail!("no such shard {shard_id}");
        };

        tx.send(msg)?;
        
        Ok(())
    }
    
    pub async fn recv_from_shard(&self, info: &ConnectionInfo) -> Result<Vec<Packet>> {
        // Wait until RX is initialized
        let rx = loop {
            if let Some(id) = info.character_id
                && let Some(rx) = self.player_rx.read().get(&id).cloned() {
                break rx;
            } else {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            };
        };

        let Ok(msg) = rx.recv_async().await else {
            bail!("receive error");
        };

        let mut out = vec![];
        
        match msg.kind {
            MessageFromShardKind::EntitySpawn { bundle } => {
                match bundle {
                    EntityBundle::Player(b) => {
                        out.push(Packet::Entity(Entity {
                            tag: U8(9),
                            kind: EntityKind::Mob(MobEntity {
                                id: U32(b.id.0),
                                mob_id: U16(467),
                                level: U16(b.level.level),
                                custom_name: b.name.name.into(),
                                hp: U32(b.health.value),
                                coords: b.pos.0.into(),
                                unk2: U8(0),
                                unk3: F32(0.5),
                                scale: F32(1.0),
                                unk5: U32(3),
                                unk6: U32(0),
                                max_hp: U32(b.health.max),
                                unk8: F32(6.0),
                                unk9: U16(0),
                                unk10: U32(0),
                                unk11: RBool(0),
                                unk12: U32(0),
                                unk13: U32(0),
                            }),
                        }));
                    },
                    EntityBundle::Mob(b) => {
                        out.push(Packet::Entity(Entity {
                            tag: U8(9),
                            kind: EntityKind::Mob(MobEntity {
                                id: U32(b.id.0),
                                mob_id: U16(b.mob.id),
                                level: U16(b.level.level),
                                custom_name: RString::empty(),
                                hp: U32(b.health.value),
                                coords: b.pos.0.into(),
                                unk2: U8(0),
                                unk3: F32(0.5),
                                scale: F32(1.0),
                                unk5: U32(3),
                                unk6: U32(0),
                                max_hp: U32(b.health.max),
                                unk8: F32(6.0),
                                unk9: U16(0),
                                unk10: U32(0),
                                unk11: RBool(0),
                                unk12: U32(0),
                                unk13: U32(0),
                            }),
                        }));
                    },
                }
            },
            MessageFromShardKind::EntityMove { id, pos } => {
                out.push(Packet::EntityMove(vec![EntityMove {
                    id: U32(id),
                    coords: pos.into(),
                    unk12: U16(0),
                    flags: U16(0),
                    unk16: U16(0),
                }]))
            },
            MessageFromShardKind::PlayerLoaded { bundle } => {
                // Message order matters
                // This must be first
                out.push(Packet::PlayerData(PlayerData {
                    unk0: U8(8),
                    id: U32(bundle.id.0),
                    class: U16(bundle.player.class),
                    level: U16(bundle.level.level),
                    unk4: U8(1),
                    unk5: U8(0),
                    unk6: U8(0),
                    name: bundle.name.name.clone().into(),
                    hp: U32(bundle.health.value),
                    mp: U32(bundle.energy.value),
                    location_id: U32(msg.shard_id),
                    coords: bundle.pos.0.into(),
                    unk13: U8(0),
                    rot: F32(0.0),
                    unk15: RBool(0),
                    alive: RBool(1),
                    unk17: RBool(0),
                    unk18: RBool(0),
                    unk19: RBool(0),
                    body: bundle.player.body,
                    hp2: U32(bundle.health.max),
                    mp2: U32(bundle.energy.max),
                    movspeed: F32(5.0),
                    unk24: U32(3183328701),
                    unk25: U32(0),
                    unk26: U32(0),
                    unk27: U32(5),
                    unk28: U32(0),
                    unk29: U8(1),
                    unk30: U32(0),
                    unk31: U32(0),
                    unk32: RString::empty(),
                    unk33: U64(0),
                    unk34: U16(0),
                    unk35: U16(0),
                    unk36: RBool(0),
                    unk37: RString::empty(),
                    unk38: U32(4),
                    effects: RVec::from(vec![]),
                    unk39: Op13([36; 4]),
                    current_exp: U32(64),
                    unk41: U32(0),
                    unk42: U16(0),
                    stats: RVec::from(vec![F32(0.0); 159]),
                    stats2: vec![F32(0.0); 159],
                    unk45: U64(0),
                    talents: RVec::from(vec![]),
                    unk47: RVec::from(vec![]),
                    unk48: U64(0),
                    unk49: F32(0.0),
                    unk50: F32(30.0),
                    unk51: U16(0),
                    unk52: U16(0),
                    unk53: U32(0),
                    unk54: U32(0),
                    unk55: U32(0),
                    unk56: [U16(36); 4],
                    unk57: U16(27),
                    unk58: [U16(20); 4],
                    unk59: U16(100),
                    unk60: CurrencyData { data: [0; 36] },
                    unk61: U8(0),
                    ach_data: RZlib::empty(),
                }));
                // let p = Packet::PlayerData(
                //     PlayerData::read(&mut std::io::Cursor::new(
                //         &include_bytes!("../../../../captures/blobs/p51_ktrunc.bin")[2..]
                //     )).unwrap()
                // );
                // out.push(p);
                
                out.push(Packet::SwitchLocation(SwitchLocation {
                    location_id: U32(msg.shard_id),
                    unk1: U32(0),
                }));

                // out.push(Packet::Inventory(Inventory{
                //     unk0: U8(1),
                //     unk1: U16(1),
                //     items: RVec::from(vec![])
                // }));

                out.push(Packet::PosCamera(PosCamera {
                    unk0: U32(0),
                    coords: bundle.pos.0.into(),
                    rot: F32(0.0),
                    unk4: U8(0),
                    movspeed: F32(5.0),
                    effects: RVec::from(vec![]),
                }));
            }
        }

        Ok(out)
    }
}

impl From<glam::Vec2> for Coords {
    fn from(value: glam::Vec2) -> Self {
        Self {
            x: F32(value.x),
            y: F32(value.y),
        }
    }
}

impl From<Coords> for glam::Vec2 {
    fn from(value: Coords) -> Self {
        Self {
            x: value.x.0,
            y: value.y.0,
        }
    }
}

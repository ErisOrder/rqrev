use clap::Parser;
use tracing::error;

use crate::server::handler::PacketOrBlob;
use crate::protocol::*;
use crate::rqode_binrw::*;

#[derive(Parser)]
enum ChatCli {
    /// Change location
    Loc {
        id: u32,
    },
    /// Spawn mob
    Spawnmob {
        id: u16,
        hp: u32,
    },
    /// Give item
    Give {
        id: u32,
        quant: u16,
    }
}

pub fn process_cli_command(text: &str, out: &mut Vec<PacketOrBlob>) -> Option<()> {
    let args = match ChatCli::try_parse_from(["RQ"].into_iter().chain(text.split_whitespace())) {
        Ok(a) => a,
        Err(e) => {
            error!("command parse error: {e}");
            // out.push(PacketOrBlob::Packet(Packet::ChatMessage(ChatMessage {
            //     chat_id: Op21(0x0),
            //     text: e.to_string().into(),
            //     name: "SRV".into(),
            // })));
            return None;
        },
    };

    match args {
        ChatCli::Loc { id } => {
            out.push(PacketOrBlob::Packet(Packet::SwitchLocation(SwitchLocation {
                location_id: U32(id),
                unk1: U32(0),
            })));
            out.push(PacketOrBlob::Packet(Packet::PosCamera(PosCamera {
                unk0: U32(0),
                coords: Coords {
                    x: F32(0.0),
                    y: F32(0.0),
                },
                rot: F32(0.0),
                unk4: U8(1),
                movspeed: F32(20.0),
                effects: RVec::from(vec![]),
            })));
        },
        ChatCli::Spawnmob { id, hp } => {
            out.push(PacketOrBlob::Packet(Packet::Entity(Entity {
                tag: U8(9),
                kind: EntityKind::Mob(MobEntity {
                    id: U32(1000),
                    mob_id: U16(id),
                    level: U16(1),
                    custom_name: RString::empty(),
                    hp: U32(hp),
                    coords: Coords {
                        x: F32(0.0),
                        y: F32(0.0),
                    },
                    unk2: U8(0),
                    unk3: F32(0.5),
                    scale: F32(1.0),
                    unk5: U32(3),
                    unk6: U32(0),
                    max_hp: U32(hp),
                    unk8: F32(6.0),
                    unk9: U16(0),
                    unk10: U32(0),
                    unk11: RBool(0),
                    unk12: U32(0),
                    unk13: U32(0),
                }),
            })));
        },
        ChatCli::Give { id, quant } => {
            out.push(PacketOrBlob::Packet(Packet::ReceiveItem(ReceiveItem {
                unk0: U8(1),
                item: ItemDesc {
                    slot: InvSlot { idx: 1, unk1: 0, tab: 2, inv: 2 },
                    id: U32(id),
                    count: U16(quant),
                    flags: U32(0),
                    unk5: None,
                    unk6: None,
                    ext: None
                }
            })));
        }
    }

    Some(())
}

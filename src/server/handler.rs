use binrw::BinWrite;
use tracing::{error, info};

use crate::{protocol::*, rqode_binrw::*, server::{State, cli::process_cli_command}};

#[derive(BinWrite)]
#[bw(little)]
pub enum PacketOrBlob {
    Packet(Packet),
    Blob(&'static [u8])
}

pub async fn process_packet(state: &State, p: &mut Packet) -> Vec<PacketOrBlob> {
    let mut out = vec![];
    match p {
        Packet::AuthRequest(p) => {
            let p = Packet::ServerList(ServerList {
                servers: RVec::from(vec![
                    ServerDesc {
                        id: U16(4),
                        name: "Eris Order".into(),
                        unk1: U32(2)
                    }
                ]),
                // For now replicate exactly
                // I haven't figured out it yet
                // If you fail, game will either crash or stuck in server select
                unk1: RVec { data: vec![U16(4), U16(6), U16(5), U16(0), U16(6), U16(0), U16(7), U16(0), U16(8), U16(0)] }, 
                unk2: RVec { data: vec![U16(0), U16(10), U16(0), U16(11), U16(0), U16(12), U16(9), U16(51), U16(0)] }, 
                endpoints: RVec::from(vec![
                    EndpointDesc {
                        server_id: U16(4),
                        ip: "224.53.9.37".parse().unwrap(),
                        port: U16(4254),
                        unk3: U16(18),
                    }
                ]),
                unk4: U32(0),
                unk5: RBool(0),
                unk6: U32(0),
                unixtime: U64(chrono::Utc::now().timestamp() as u64),
                unk8: U32(579773625),
                mb_selected_server_id: U16(4),
                unk10: U64(10800),
                unk11: [2].into(),
                unk12: U32(328192),
                xkey0: U32(10055125),
                xkey1: U64(884273655149372),
                rdtsc_echo: p.rdtsc,
                unk16: RString::empty(),
            });
            
            out.push(PacketOrBlob::Packet(p));
        },
        // Packet::PinResult(pin_result) => todo!(),
        Packet::Connect(p) => {
            out.push(PacketOrBlob::Packet(Packet::TimeSync(TimeSync {
                unixtime: U64(chrono::Utc::now().timestamp() as u64) 
            })));
        },
        Packet::TimeSyncResponse(p) => {
            let p = Packet::CharList(CharList {
                xkey0: p.xkey0,
                unk1: U64(10800),
                unk2: U32(0),
                some_flags: U32(512),
                unk4: U32(0),
                rdtsc_echo: p.rdtsc,
                unk5: RString::empty(),
                unk6: U32(0),
                // Empty slots required for new characters
                chars: RVec::from(vec![
                    CharacterSlot { id: U32(34), info: Some(CharacterInfo {
                        class: U16(4),
                        sex: RBool(0),
                        level: U16(999),
                        unk3: U32(0),
                        hp: U32(100),
                        mp: U32(100),
                        location_id: U32(25565),
                        body: BodyParam {
                            haircolor: 0,
                            unk1: 0,
                            skin: 0,
                            unk3: 0,
                            unk4: 0,
                            face: 0,
                            unk6: 0,
                            unk7: 0
                        },
                        name: "Еби гусей".into(),
                        unk9: U8(0),
                        unk10: U64(0),
                        equip: RVec::from(starter_pack())
                    }) },
                    CharacterSlot { id: U32(0), info: None },
                    CharacterSlot { id: U32(0), info: None },
                    CharacterSlot { id: U32(0), info: None },
                ]),
            });
            out.push(PacketOrBlob::Packet(p));
        },
        Packet::HeartbeatClient(p) => {
            out.push(PacketOrBlob::Packet(Packet::HeartbeatServer(HeartbeatServer {
                id: p.id,
                time: U32(0),
            })));
        },
        Packet::EnterWorldRequest(p) => {
            out.push(PacketOrBlob::Packet(Packet::EnterWorldResponse(EnterWorldResponse {
                unk: U16(0),
            })));
            out.push(PacketOrBlob::Packet(Packet::Inventory(Inventory{
                unk0: U8(1),
                unk1: U16(1),
                items: RVec::from(starter_pack())
            })));
            // Game crashes without this packet
            // Certainly contains character info
            out.push(PacketOrBlob::Blob(
                include_bytes!("../../../captures/blobs/p51_ktrunc.bin")
            ));
            out.push(PacketOrBlob::Packet(Packet::SwitchLocation(SwitchLocation {
                location_id: U32(25565),
                unk1: U32(0),
            })));
            out.push(PacketOrBlob::Packet(Packet::PosCamera(PosCamera {
                unk0: U32(0),
                coords: Coords {
                    x: F32(130.0),
                    y: F32(108.0),
                },
                rot: F32(0.0),
                unk4: U8(0),
                movspeed: F32(5.0),
                effects: RVec::from(vec![]),
            })));
        }
        // Packet::ChatMessage(chat_message) => todo!(),
        // Packet::CharacterMove(character_move) => todo!(),
        // Packet::Attack(attack) => todo!(),
        // Packet::PickupRequest(pickup_request) => todo!(),
        Packet::MoveItemRequest(p) => {
            out.push(PacketOrBlob::Packet(Packet::MoveItemResponse(
                p.clone()
            )));
        },
        Packet::SendChatMessage(p) => {
            // FIXME: Does not work
            out.push(PacketOrBlob::Packet(Packet::ChatMessage(ChatMessage {
                chat_id: Op21(0x0),
                text: p.text.clone(),
                name: "SRV".into(),
            })));
        }
        Packet::ShowEmotion(p) => {
            process_cli_command(&p.emo.data, &mut out);
        }
        // Packet::StatUpdateRequest(stat_update_request) => todo!(),
        // Packet::BuyItemRequest(buy_item_request) => todo!(),
        // Packet::SellItemRequest(sell_item_request) => todo!(),
        // Packet::BuyBackRequest(buy_back) => todo!(),
        // Packet::CompressedData(compressed_data) => todo!(),
        // Packet::ShowEmotion(show_emotion) => todo!(),
        Packet::Heartbeat2(p) => {
            out.push(PacketOrBlob::Packet(Packet::Heartbeat2(Heartbeat2 {
                client_uptime: p.client_uptime,
            })));
        },
        Packet::ExitRequest(p) => {
            // TODO: Send init packets depending on type
            out.push(PacketOrBlob::Packet(Packet::ExitResponse(ExitResponse {
                unk: U32(0),
            })));
            out.push(PacketOrBlob::Packet(Packet::ConnectionError(ConnectionError {
                code: U32(100),
            })));
        }
        Packet::ConnectionClose2() => {
            info!("connection closed");
        }
        other => {
            error!("unexpected packet from client: {other:?}");
        }
    }
    
    out
}


pub fn starter_pack() -> Vec<ItemDesc> {
    vec![
        ItemDesc {
            // Chest armor
            slot: InvSlot { idx: 3, unk1: 0, tab: 0, inv: 1 },
            id: U32(5143),
            count: U16(1),
            flags: U32(0x0000),
            unk5: None,
            unk6: None,
            ext: None
        },
        ItemDesc {
            // Right hand weapon 
            slot: InvSlot { idx: 4, unk1: 0, tab: 0, inv: 1 },
            id: U32(309),
            count: U16(1),
            flags: U32(0x0000),
            unk5: None,
            unk6: None,
            ext: None
        },
        ItemDesc {
            // Left hand weapon 
            slot: InvSlot { idx: 5, unk1: 0, tab: 0, inv: 1 },
            id: U32(2244),
            count: U16(1),
            flags: U32(0x0000),
            unk5: None,
            unk6: None,
            ext: None
        },
    ]
}

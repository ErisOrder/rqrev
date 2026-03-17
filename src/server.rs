use std::{io::{Cursor, Seek, SeekFrom}, sync::Arc};

use num_enum::TryFromPrimitive;
use pretty_hex::PrettyHex;
use ringbuf::{HeapRb, traits::{Consumer, Observer, Producer}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tracing::{debug, error, info, trace, warn};

use binrw::{BinRead, BinWrite};

use crate::{cipher::{CustomRc4, prepare_rc4_boxes, read_game_pubkey}, protocol::*, ptrace::ptrace, rqode_binrw::BinReadChecked};
use crate::mitm::PacketSource;
use crate::rqode_binrw::*;

pub struct State {
    
}

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
        tokio::spawn(connection_proc(self.state.clone(), stream));
    }
}

pub enum ConnectionState {
    Uninit,
    Encrypted {
        // Generated RX and TX
        game_rx: CustomRc4,
        game_tx: CustomRc4,
    }
}

async fn connection_proc(state: Arc<State>, mut conn: TcpStream) {
    let mut cstate = ConnectionState::Uninit;
    let mut rxbuf = HeapRb::new(1000000);
    let addr = conn.peer_addr().unwrap();

    info!("start connection {addr} task");
    
    let mut rbuf = vec![0u8; 0x10000];
    let mut response = vec![];
    loop {
        match conn.read(&mut rbuf).await {
            Ok(0) => {
                info!("connection {addr} closed");
                return;
            }
            Ok(sz) => {
                let data = &mut rbuf[..sz];
                match &mut cstate {
                    ConnectionState::Uninit => {
                        // Expect game pubkey
                        if data.len() == 132 {
                            debug!("accepted game pubkey");
                            
                            let pubk = match read_game_pubkey(data) {
                                Ok(pubk) => pubk,
                                Err(e) => {
                                    error!("read pubkey error: {e}");
                                    continue;
                                },
                            };

                            let (game_rx, game_tx, out) = prepare_rc4_boxes();

                            // TODO: Encrypt

                            cstate = ConnectionState::Encrypted { game_rx, game_tx };
                            response = out;
                        }
                    },
                    ConnectionState::Encrypted { game_rx, game_tx } => {
                        // Decrypt data from client
                        game_tx.xor_in_place(data);

                        // Process packets
                        let mut resp = process_client_data(&state, &mut rxbuf, data).await;
                        
                        // Encrypt data for client
                        game_rx.xor_in_place(&mut resp);

                        response = resp;
                    },
                }
            },
            Err(e) => {
                error!("connection {addr} error: {e}");
                return;
            },
        }

        if !response.is_empty() {
            match conn.write_all(&response).await {
                Ok(_) => (),
                Err(e) => {
                    error!("connection {addr} error: {e}");
                    return;
                }
            }
        }
    }
}

async fn process_client_data(
    state: &State,
    rxbuf: &mut HeapRb<u8>,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Cursor::new(vec![]);

    // Push bytes to ringbuffer
    rxbuf.push_slice(&data);

    let mut temp = vec![];

    loop {
        if rxbuf.occupied_len() < 4 {
            break
        }

        // Peek packet len & type
        let mut headr = [0u16, 0u16];
        rxbuf.peek_slice(bytemuck::cast_slice_mut(&mut headr));
        let [size, ptype] = headr;
        
        // If buffer has not enough data
        if rxbuf.occupied_len() < size as usize {
            break
        }
        
        // Pop packet data
        temp.resize(size as usize, 0);
        rxbuf.pop_slice(&mut temp);
        
        let known_ptype = PacketType::try_from_primitive(ptype).ok();
        
        let desc = known_ptype
            .map(|t| format!("{t:?}"))
            .unwrap_or_default();
        
        let packet = &temp[2..size as usize];    

        if known_ptype.is_none() {
            ptrace(PacketSource::Client, ptype, packet);
            warn!("skip unknown packet {ptype:#02x} ({ptype}): {desc}");
            continue;
        }

        // Try to read it
        match Packet::read_checked(packet) {
            Ok(mut p) => {
                ptrace(PacketSource::Client, ptype, packet);
                let resp = process_packet(state, &mut p).await;
                for p in resp {
                    let start = out.position() as usize;
                    0u16.write_le(&mut out).unwrap();
                    p.write(&mut out).unwrap();
                    let end = out.position() as usize;
                    let size = (end - start) as u16;
                    out.seek(SeekFrom::Start(start as u64)).unwrap();
                    size.write_le(&mut out).unwrap();
                    let ptype = u16::read_le(&mut out).unwrap();
                    out.seek(SeekFrom::Start(end as u64)).unwrap();
                                        
                    let slice = &out.get_ref()[start + 2..end];
                    ptrace(PacketSource::Server, ptype, slice);
                }                
            },
            Err(e) => {
                warn!("skip packet {ptype:#02x} ({ptype}): {desc}: {e}");
            },
        }
        
    }

    out.into_inner()
}

#[derive(BinWrite)]
#[bw(little)]
enum PacketOrBlob {
    Packet(Packet),
    Blob(&'static [u8])
}

async fn process_packet(state: &State, p: &mut Packet) -> Vec<PacketOrBlob> {
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
                        name: "Казума".into(),
                        unk9: U8(0),
                        unk10: U64(0),
                        equip: RVec::from(vec![
                            ItemDesc {
                                // Chest armor
                                slot: InvSlot { idx: 3, unk1: 0, tab: 0, inv: 1 },
                                id: U32(5143),
                                count: U16(1),
                                flags: U32(0x0000),
                                unk5: None,
                                unk6: None,
                                ext: None
                            }
                        ])
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
                items: RVec::from(vec![
                    ItemDesc {
                        // Chest armor
                        slot: InvSlot { idx: 3, unk1: 0, tab: 0, inv: 1 },
                        id: U32(5143),
                        count: U16(1),
                        flags: U32(0x0000),
                        unk5: None,
                        unk6: None,
                        ext: None
                    }
                ])
            })));
            // Game crashes without this packet
            // Certainly contains character info
            out.push(PacketOrBlob::Blob(
                include_bytes!("../../captures/blobs/p51.bin")
            ));
            out.push(PacketOrBlob::Packet(Packet::SwitchLocation(SwitchLocation {
                location_id: U32(25565),
                unk1: U32(0),
            })));
            out.push(PacketOrBlob::Packet(Packet::PosCamera(PosCamera {
                unk0: U32(0),
                x: F32(130.0),
                y: F32(108.0),
                rot: F32(0.0),
                unk4: U8(0),
                unk5: F32(5.0),
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


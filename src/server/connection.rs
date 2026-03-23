
use std::{io::{Cursor, Seek, SeekFrom}, sync::Arc};

use num_enum::TryFromPrimitive;
use pretty_hex::PrettyHex;
use ringbuf::{HeapRb, traits::{Consumer, Observer, Producer}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tracing::{debug, error, info, trace, warn};

use binrw::{BinRead, BinWrite};

use crate::{cipher::{CustomRc4, prepare_rc4_boxes, read_game_pubkey}, protocol::{Packet, PacketType}, ptrace::ptrace, rqode_binrw::BinReadChecked, server::handler::PacketOrBlob };
use crate::mitm::PacketSource;

use super::*;

pub struct ConnectionState {
    cipher: CipherState,
    cinfo: ConnectionInfo,
    rxbuf: HeapRb<u8>,
}

pub struct ConnectionInfo {
    pub session: Option<u64>,
    pub character_id: Option<u32>,
    pub shard_id: Option<u32>,
}

impl ConnectionState {
    pub fn new() -> Self {
        Self {
            cipher: CipherState::Uninit,
            cinfo: ConnectionInfo {
                session: None,
                character_id: None,
                shard_id: None,
            },
            rxbuf: HeapRb::new(1000000),
        }
    }
}

#[derive(Default)]
pub enum CipherState {
    #[default]
    Uninit,
    Encrypted {
        // Generated RX and TX
        game_rx: CustomRc4,
        game_tx: CustomRc4,
    }
}

pub async fn connection_proc(state: Arc<State>, mut conn: TcpStream) {
    let mut cstate = ConnectionState::new();
    
    let addr = conn.peer_addr().unwrap();

    info!("start connection {addr} task");
    
    let mut rbuf = vec![0u8; 0x10000];
    let mut response = vec![];

    enum Res {
        Client(std::io::Result<usize>),
        Server(anyhow::Result<Vec<Packet>>),
    }
    
    loop {
        let res = tokio::select! {
            res = conn.read(&mut rbuf) => {
                Res::Client(res)
            },
            res = state.recv_from_shard(&cstate.cinfo) => {
                Res::Server(res)
            }
        };

        match res {
            Res::Client(res) => match res {
                Ok(0) => {
                    info!("connection {addr} closed");
                    return;
                }
                Ok(sz) => {
                    let data = &mut rbuf[..sz];
                    match &mut cstate.cipher {
                        CipherState::Uninit => {
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

                                cstate.cipher = CipherState::Encrypted { game_rx, game_tx };
                                response = out;
                            }
                        },
                        CipherState::Encrypted { game_rx, game_tx } => {
                            // Decrypt data from client
                            game_tx.xor_in_place(data);

                            // Process packets
                            let mut resp = process_client_data(
                                &state,
                                &mut cstate.rxbuf,
                                &mut cstate.cinfo,
                                data
                            ).await;
                    
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
            },
            Res::Server(res) => match res {
                Ok(packets) => {
                    if let CipherState::Encrypted { game_rx, .. } = &mut cstate.cipher {
                        let mut resp = Cursor::new(vec![]);
                        
                        for p in packets {
                            let (ptype, slice) = write_packet(&mut resp, &PacketOrBlob::Packet(p));
                            ptrace(PacketSource::Server, ptype, slice);
                        }

                        let mut resp = resp.into_inner();
                        
                        // Encrypt data for client
                        game_rx.xor_in_place(&mut resp);

                        response = resp;
                    }
                },
                Err(e) => {
                    error!("server error: {e}");
                    continue;
                },
            }
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
    info: &mut ConnectionInfo,
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
            Ok(p) => {
                ptrace(PacketSource::Client, ptype, packet);
                match super::handler::process_packet(state, info, p).await {
                    Ok(resp) => {
                        for p in resp {
                            let (ptype, slice) = write_packet(&mut out, &p);     
                            ptrace(PacketSource::Server, ptype, slice);
                        }                
                    },
                    Err(e) => {
                        error!("packet handle error: {e}");
                    },
                }
                
            },
            Err(e) => {
                warn!("skip packet {ptype:#02x} ({ptype}): {desc}: {e}");
                match Packet::read_partial(packet) {
                    Ok((p, len)) => {
                        warn!("partial: {p:?}\nrest: {:#?}", packet[len..].hex_dump());
                    },
                    Err(e) => {
                        warn!("partial read failed: {e}");
                    },
                }
            },
        }
        
    }

    out.into_inner()
}

fn write_packet<'a>(curs: &'a mut Cursor<Vec<u8>>, p: &PacketOrBlob) -> (u16, &'a [u8]) {
    let start = curs.position() as usize;

    // Write stub size
    0u16.write_le(curs).unwrap();
    
    // Serialize packet
    p.write(curs).unwrap();
    
    // Calculate size
    let end = curs.position() as usize;
    let size = (end - start) as u16;
    
    // Write size
    curs.seek(SeekFrom::Start(start as u64)).unwrap();
    size.write_le(curs).unwrap();

    // Read ptype
    let ptype = u16::read_le(curs).unwrap();

    // Rewind
    curs.seek(SeekFrom::Start(end as u64)).unwrap();

    let slice = &curs.get_ref()[start + 2..end];
    (ptype, slice)
}

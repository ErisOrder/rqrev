
use std::{io::{Cursor, Seek, SeekFrom}, sync::Arc};

use clap::Parser;
use num_enum::TryFromPrimitive;
use pretty_hex::PrettyHex;
use ringbuf::{HeapRb, traits::{Consumer, Observer, Producer}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tracing::{debug, error, info, trace, warn};

use binrw::{BinRead, BinWrite};

use crate::{cipher::{CustomRc4, prepare_rc4_boxes, read_game_pubkey}, ptrace::ptrace, rqode_binrw::BinReadChecked, };
use crate::mitm::PacketSource;

use super::*;

pub enum ConnectionState {
    Uninit,
    Encrypted {
        // Generated RX and TX
        game_rx: CustomRc4,
        game_tx: CustomRc4,
    }
}

pub async fn connection_proc(state: Arc<State>, mut conn: TcpStream) {
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
                let resp = super::handler::process_packet(state, &mut p).await;
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


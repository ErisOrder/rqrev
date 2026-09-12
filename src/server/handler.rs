use binrw::BinWrite;
use tracing::{error, info};

use crate::server::{cli::process_cli_command, connection::ConnectionInfo, prelude::*};

#[derive(BinWrite)]
#[bw(little)]
pub enum PacketOrBlob {
    Packet(Packet),
    Blob(&'static [u8])
}

pub async fn process_packet(
    state: &State,
    info: &mut ConnectionInfo,
    p: Packet
) -> Result<Vec<PacketOrBlob>> {
    let mut out = vec![];
    match p {
        // Auth-related packets
        Packet::AuthRequest(p) => {
            let p = state.handle_auth_request(info, p).await?;
            let p = Packet::ServerList(p);
            
            out.push(PacketOrBlob::Packet(p));
        },
        Packet::Connect(p) => {
            out.push(PacketOrBlob::Packet(Packet::TimeSync(TimeSync {
                unixtime: U64(state.timestamp()) 
            })));
        },
        Packet::TimeSyncResponse(p) => {
            let p = state.handle_charlist_req(info, p).await?;
            let p = Packet::CharList(p);
            
            out.push(PacketOrBlob::Packet(p));
        },
        Packet::EnterWorldRequest(p) => {
            let p = state.handle_enter_world_req(info, p).await?;
            let p = Packet::EnterWorldResponse(p);
            
            out.push(PacketOrBlob::Packet(p));
            
            // // Game crashes without this packet
            // // Certainly contains character info
            // out.push(PacketOrBlob::Blob(
            //     include_bytes!("../../../captures/blobs/p51_ktrunc.bin")
            // ));
        }

        // Heartbeats
        Packet::HeartbeatClient(p) => {
            out.push(PacketOrBlob::Packet(Packet::HeartbeatServer(HeartbeatServer {
                id: p.id,
                time: U32(state.uptime()),
            })));
        },
        Packet::Heartbeat2(p) => {
            out.push(PacketOrBlob::Packet(Packet::Heartbeat2(Heartbeat2 {
                client_uptime: p.client_uptime,
            })));
        },
        
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
            process_cli_command(&p.emo.into_string(), &mut out);
        }
        // Packet::StatUpdateRequest(stat_update_request) => todo!(),
        // Packet::BuyItemRequest(buy_item_request) => todo!(),
        // Packet::SellItemRequest(sell_item_request) => todo!(),
        // Packet::BuyBackRequest(buy_back) => todo!(),
        Packet::ExitRequest(p) => {
            // TODO: Send init packets depending on type
            out.push(PacketOrBlob::Packet(Packet::ExitResponse(ExitResponse {
                delay: U32(0),
            })));
            out.push(PacketOrBlob::Packet(Packet::ConnectionError(ConnectionError {
                code: U32(100),
            })));
        }
        Packet::ConnectionClose2() => {
            info!("connection closed");
        }
        other => {
            state.send_packet_to_shard(info, other)?;
        }
    }
    
    Ok(out)
}



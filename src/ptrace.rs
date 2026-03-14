use std::io::Cursor;

use num_enum::TryFromPrimitive;
use pretty_hex::PrettyHex;

use crate::{cipher::PacketSource, protocol::{Packet, PacketType}, rqode_binrw::BinReadChecked};

const IGNORE: &[PacketType] = &[
    PacketType::HeartbeatClient,
    PacketType::HeartbeatServer,
    PacketType::Heartbeat2,
    
    PacketType::CharacterMove,  
    PacketType::EntityMove,
];

const COLLAPSE: &[PacketType] = &[
    PacketType::GuildAvatar,
    PacketType::ServerVars,
];

const ONLY: &[PacketType] = &[
    
];

pub fn ptrace(
    source: PacketSource,
    ptype: u16,
    data: &mut [u8],
) {
    let sptype = PacketType::try_from_primitive(ptype);

    let (sptype, collapse) = match sptype {
        Ok(t) => {
            if IGNORE.contains(&t) {
                return;
            }
            if !ONLY.is_empty() && !ONLY.contains(&t) {
                return;
            }
            
            (format!("{t:?}"), COLLAPSE.contains(&t))
        },
        Err(_) => {
            if !ONLY.is_empty() {
                return;
            }
            
            (String::new(), false)
        },
    };

    println!("--- --- --- --- --- --- --- --- --- --- --- --- --- ---");
    if collapse || data.len() == 2 {
        println!("{source:?}: packet {ptype:#02X} ({ptype:02}) {sptype}; Length {}", data.len() - 2);
        return;
    }

    let parsed = Packet::read_partial(&data[..]);
    match parsed {
        Ok((Packet::CompressedData(mut packet), _)) => {
            let mut header = [0u16, 0u16];
            bytemuck::cast_slice_mut(&mut header).copy_from_slice(&packet.blob[..4]);
            
            ptrace(source, header[1], &mut packet.blob[2..]);
            return;
        },
        Ok((packet, offset)) => {
            println!("{source:?}: packet {ptype:#02X} ({ptype:02}) {sptype}\nparsed: {packet:?}");
            let left = &data[offset..];
            if !left.is_empty() {
                println!("left: {:#?}", left.hex_dump());
                let res = crate::rqode_binrw::read_guess_all(Cursor::new(left));
                match res {
                    Ok(p) => println!("parsed: {p:?}"),
                    Err(e) => println!("parse error: {}", e.root_cause().to_string().lines().next().unwrap()),
                }
            }
            return;
        }
        Err(e) => {
            if !sptype.is_empty() {
                println!("parse error: {e}");
            }
        },
        // Err(e) => println!("partial parse error: {e}"),
    }
    
    println!("{source:?}: packet {ptype:#02X} ({ptype:02}) {sptype}; {:#?}", data[2..].hex_dump());
    let res = crate::rqode_binrw::read_guess_all(Cursor::new(&data[2..]));
    match res {
        Ok(p) => println!("parsed: {p:?}"),
        Err(e) => println!("parse error: {}", e.root_cause().to_string().lines().next().unwrap()),
    }
}

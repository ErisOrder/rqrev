//! Typical packet structure:
//! u16 size (incl. this field)
//! u16 type
//! variable data
//!
//! packet contents seems to be opcode-prefixed data types
//! 
//! strings and byte arrays are not distinguished easily,
//! they are represented as U16 len, variable data

use serde::{Deserialize, Serialize};


#[repr(u16)]
pub enum PacketType {
    /// Client -> Server
    /// auth data
    AuthRequest = 0x01,
    /// Client -> Server
    /// pincode hash and smth
    PinResult = 0x06,
    /// Client -> Server
    /// close connection, no data
    ConnectionClose = 0x08,
    CharList = 0x11,
    /// Cleint -> Server
    /// another connection close, no data
    ConnectionClose2 = 0x56,

    /// Client -> Server
    /// Name availability testing, single string
    TestCharNameReq = 0x3f,
    /// Server -> Client
    /// Name avail response, single u32
    TestCharNameResp = 0x40,

    /// Server -> Client
    ChatMessage = 0x78,
    
    // KeepAliveClient = 0x46,
    // KeepAliveServer = 0x47,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PinResult {
    pub pin_hash: String,
    /// Not a "remember", probably
    /// Remeber seems to be client-side
    /// Client sends pin hash in auth req
    pub bool0: bool,
    /// Maybe OK/CLOSE result
    pub bool1: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Packet4 {
    pub unk0: u16,
    pub unk1: u16,
}


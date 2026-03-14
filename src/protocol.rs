//! Typical packet structure:
//! u16 size (incl. this field)
//! u16 type
//! variable data
//!
//! packet contents seems to be opcode-prefixed data types
//! 
//! strings and byte arrays are not distinguished easily,
//! they are represented as U16 len, variable data

use binrw::{BinRead, BinResult, binrw, helpers::until_eof};
use pretty_hex::PrettyHex;
use crate::rqode_binrw::*;

#[derive(Clone, Copy, Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive, PartialEq, Eq)]
#[repr(u16)]
pub enum PacketType {
    /// Client -> Server
    /// auth data
    AuthRequest = 0x01,

    /// Server -> Client
    /// Contains list of servers
    ServerList = 0x02,
    
    /// Client -> Server
    /// pincode hash and smth
    PinResult = 0x06,
    /// Client -> Server
    /// close connection, no data
    ConnectionClose = 0x08,

    /// Client -> Server
    /// Sent when player presses server select button
    /// Empty
    FetchServerList = 0x09,

    /// Server -> Client
    /// Contains list of servers
    /// Resposnse to 0x09
    /// Similar to 0x02, but somewhat truncated
    ServerListResponse = 0x0A,

    /// Client -> Server
    /// Sent on connection start
    /// Contains millis from PC start, and millis + 354
    Connect = 0x0C,
    
    /// Server -> Client
    /// Server sends its time
    /// Client must respond with packet 0xF (TimeSyncResponse)
    /// Causes time diff calculation on client
    TimeSync = 0x0D,

    /// Client -> Server
    /// Contains some unknown fields derived from global vars
    TimeSyncResponse = 0x0F,
    
    /// Server -> Client
    ConnectionError = 0x0E,
    
    /// Server -> Client
    /// Contains characters and their equipment
    AccountInfo = 0x11,

    /// Client -> Server
    /// Sent when player enters premium ccode 
    PremiumCode = 0x1C,
    
    /// Server -> Client
    /// Premium code validtion result
    PremiumCodeResponse = 0x1D,

    /// Server -> Client
    /// Sent on startup
    ServerVars = 0x12,

    /// Server -> Client
    Packet13 = 0x13,

    /// Client -> Server
    /// DLC id
    SteamDlcInstalled = 0x25,
    
    /// Client -> Server
    /// Issued when user presses "take reward" on char select screen
    TakeReward = 0x24,

    /// Client -> Server
    /// Steam microtransaction
    /// order id, authorized, 
    SteamMicroTxn = 0x28,

    /// Server -> Client
    /// Inventory state
    Inventory = 0x38,

    /// Client -> Server
    /// Name availability testing, single string
    TestCharNameReq = 0x3f,
    /// Server -> Client
    /// Name avail response, single u32
    TestCharNameResp = 0x40,
    
    /// Client -> Server
    HeartbeatClient = 0x46,
    /// Server -> Client
    HeartbeatServer = 0x47,
    
    /// Server -> Client
    ChatMessage = 0x4E,

    /// Server -> Client
    /// Sent when player balance (at least gold) updated
    UpdateBalance = 0x52,
    
    /// Cleint -> Server
    /// another connection close, no data
    ConnectionClose2 = 0x56,

    /// Server -> Client
    /// Sent when new entity detected nearby
    EntityAdd = 0x5A,
    
    /// Server -> Client
    /// Sent when new entity moves
    EntityMove = 0x5C,

    /// Server -> Client
    /// Sent when entity was removed (or disappear?)
    EntityRemove = 0x5E,
    
    /// Server -> Client
    /// Sent when entity was removed (or disappear?)
    EntityRemove2 = 0x5B,
    
    /// Client -> Server
    /// Move player character
    CharacterMove = 0x5F,
    
    /// Client -> Server
    /// Sent when player attacks entity
    Attck = 0x92,
    
    /// Client -> Server
    /// Sent when player wants to pickup dropped item
    PickupRequest = 0x95,

    /// Server -> Client
    /// Sent when any player deals damage to entity
    DealtDamage = 0x9C,

    /// Server -> Client
    EntityDeath = 0xA4,

    /// Server -> Client
    /// Sent when entity dies and player receives experience
    /// And gold?
    /// Works in both directions?
    CurrencyDiff = 0xAE,

    /// Server -> Client
    /// Sent when character stat gets updated
    StatUpdate = 0xA7,
    
    /// Client -> Server
    /// Sent when player moves item in inventory
    MoveItemRequst = 0xBB,

    /// Server -> Client
    /// Move item confirmation
    MoveItem = 0xBE,

    /// Server -> Client
    /// Sent when player receives item
    ReceiveItem = 0xC1,
    
    /// Client -> Server
    /// Sent when player increases character stat
    StatUpdateRequest = 0xCD,

    /// Client -> Server
    /// Sent when player buys item from NPC
    BuyItemRequest = 0x103,

    /// Client -> Server
    /// Sent when player sells items to NPC
    SellItemRequest = 0x105,

    /// Client -> Server
    /// Sent when player buys back their items
    BuyBackRequest = 0x106,
    
    /// Client -> Server
    /// BuyBack confirmation
    BuyBack = 0x107,

    /// Both directions
    /// zlib+deflate compressed blob
    /// Might optionally be encoded using `yasli` lib
    /// Usually contains regular packet with size over some threshold
    CompressedData = 0x129,
    
    /// Server -> Client
    /// Contains PNG avatar of guild?
    GuildAvatar = 0x148,
    
    /// Server -> Client
    ShowEmotion = 0x194,

    /// Client -> Server
    ShowEmotionRequest = 0x196,

    /// Both directions
    /// Client initiates and server echoes some timestamp
    Heartbeat2 = 0x199,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    #[brw(magic(0x01u16))]
    AuthRequest(AuthRequest),
    #[brw(magic(0x02u16))]
    ServerList(ServerList),
    #[brw(magic(0x04u16))]
    Packet04(Packet04),
    #[brw(magic(0x06u16))]
    PinResult(PinResult),
    #[brw(magic(0x0Cu16))]
    Connect(Connect),
    #[brw(magic(0x0Du16))]
    TimeSync(TimeSync),
    #[brw(magic(0x0Eu16))]
    ConnectionError(ConnectionError),
    #[brw(magic(0x0Fu16))]
    TimeSyncResponse(TimeSyncResponse),
    #[brw(magic(0x12u16))]
    ServerVars(ServerVars),
    #[brw(magic(0x13u16))]
    Packet13(Packet13),
    #[brw(magic(0x46u16))]
    HeartbeatClient(HeartbeatClient),
    #[brw(magic(0x47u16))]
    HeartbeatServer(HeartbeatServer),
    #[brw(magic(0x4Eu16))]
    ChatMessage(ChatMessage),
    #[brw(magic(0x52u16))]
    UpdateBalance(UpdateBalance),
    #[brw(magic(0x5Au16))]
    Entity(Entity),
    #[brw(magic(0x5Cu16))]
    EntityMove(#[br(parse_with = until_eof)] Vec<EntityMove>),
    #[brw(magic(0x5Eu16))]
    EntityRemove(EntityRemove),
    #[brw(magic(0x5Bu16))]
    EntityRemove2(EntityRemove),
    #[brw(magic(0x5Fu16))]
    CharacterMove(CharacterMove),
    #[brw(magic(0x92u16))]
    Attack(Attack),
    #[brw(magic(0x95u16))]
    PickupRequest(PickupRequest),
    #[brw(magic(0x9Cu16))]
    DealtDamage(DealtDamage),
    #[brw(magic(0xA4u16))]
    EntityDeath(EntityDeath),
    #[brw(magic(0xAEu16))]
    CurrencyDiff(CurrencyDiff),
    #[brw(magic(0xA7u16))]
    StatUpdate(StatUpdate),
    #[brw(magic(0xBBu16))]
    MoveItemRequest(MoveItem),
    #[brw(magic(0xBEu16))]
    MoveItemResponse(MoveItem),
    #[brw(magic(0xC1u16))]
    ReceiveItem(ReceiveItem),
    #[brw(magic(0xCDu16))]
    StatUpdateRequest(StatUpdateRequest),
    #[brw(magic(0x103u16))]
    BuyItemRequest(BuyItemRequest),
    #[brw(magic(0x105u16))]
    SellItemRequest(SellItemRequest),
    #[brw(magic(0x106u16))]
    BuyBackRequest(BuyBack),
    #[brw(magic(0x107u16))]
    BuyBackResponse(BuyBack),
    #[brw(magic(0x129u16))]
    CompressedData(CompressedData),
    #[brw(magic(0x196u16))]
    ShowEmotion(ShowEmotion),
    #[brw(magic(0x199u16))]
    Heartbeat2(Heartbeat2),
}

// Client: packet 0x1 (01) AuthRequest; Length: 175 (0xaf) bytes
// 0000:   04 51 c5 a7  00 04 ee c3  a7 00 01 10  02 21 00 32   .Q...........!.2
// 0010:   39 34 31 37  61 61 62 65  38 36 38 34  30 32 62 38   9417aabe868402b8
// 0020:   31 30 62 61  32 66 34 32  37 34 32 36  35 63 31 00   10ba2f4274265c1.
// 0030:   02 01 00 00  08 ec 34 af  c1 5c 23 00  00 02 0d 00   ......4..\#.....
// 0040:   52 53 62 41  65 38 70 62  54 4f 54 48  00 02 01 00   RSbAe8pbTOTH....
// 0050:   00 03 00 03  00 04 00 00  00 00 02 06  00 36 24 4b   .............6$K
// 0060:   fe 8c 0e 19  36 02 50 ed  52 12 99 36  00 e0 4b 3c   ....6.P.R..6..K<
// 0070:   1a b7 36 5e  0c 74 0e fd  14 36 00 00  00 00 00 00   ..6^.t...6......
// 0080:   36 00 00 00  00 00 00 04  56 af 4b c6  08 56 af 4b   6.......V.K..V.K
// 0090:   c6 a4 fd 90  cd 02 65 6e  02 01 00 00  02 01 00 00   ......en........
// 00a0:   02 01 00 00  02 08 00 63  6c 61 73 73  69 63 00      .......classic.
// parsed: [U32(10995025), U32(10994670), U8(16), "29417aabe868402b810ba2f4274265c1\0", "\0",
// U64(38881293448428), "RSbAe8pbTOTH\0", "\0", Bool(0), Bool(0), U32(0), U16(6),
// Op36(2365475620, 6414), Op36(1391284226, 39186), Op36(1011605504, 46874), Op36(242486366, 5373),
// Op36(0, 0), Op36(0, 0), U32(3326848854), U64(14812618058564874070), U16(28261), "\0", "\0",
// "\0", "classic\0"]
// parsed: AuthRequest(AuthRequest { pc_millis_shift: U32(12289203), pc_millis: U32(12288848), auth_type: U8(16), account_id: "29417aabe868402b810ba2f4274265c1\0", unk0: "\0", unk1: U64(38881293448428), sign_in_code: "RSbAe8pbTOTH\0", unk2: "\0", unk3: RBool(0), unk4: RBool(0), unk5: U32(0), unk6: RVec { data: [Op36(2365475620, 6414), Op36(1391284226, 39186), Op36(1011605504, 46874), Op36(242486366, 5373), Op36(0, 0), Op36(0, 0)] }, unk7: U32(3326848854), unk8: U64(14812618058564874070), unk9: U16(28261), unk10: "\0", unk11: "\0", unk12: "\0", gateway: "classic\0" })// 
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// time + 354
    pub pc_millis_shift: U32,
    /// Just time
    pub pc_millis: U32,
    /// /place base|steam
    /// 32  - Steam
    /// 16 - BASE
    pub auth_type: U8,
    /// /account-id <string>
    pub account_id: RString,
    pub unk0: RString,
    pub unk1: U64,
    /// /sign-in-code <string>
    pub sign_in_code: RString,
    // all these parameters are stale
    pub unk2: RString,
    pub unk3: RBool,
    pub unk4: RBool,
    pub unk5: U32,
    pub unk6: RVec<Op36>,
    pub unk7: U32,
    pub unk8: U64,
    pub unk9: U16,
    pub unk10: RString,
    pub unk11: RString,
    pub unk12: RString,
    /// /gateway classic
    pub gateway: RString,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerList {
    servers: RVec<ServerDesc>,
    // TODO: ...rest
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerDesc {
    unk0: U16,
    name: RString,
    unk1: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet04 {
    pub unk0: U16,
    pub unk1: U16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    /// time + 354
    pub pc_millis_shift: U32,
    /// Just time
    pub pc_millis: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSync {
    pub unixtime: U64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeSyncResponse {
    pub unk0: U32,
    pub rdtsc: U64,
    pub unk3: U64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerVars {
    /// Game events archive?
    pub event_info: RZlib,
    /// Contains char ranges and http|ftp mentions
    pub some_regex: RZlib,
    /// "ru"
    pub mb_region: RString,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet13 {
    pub unk: RZlib,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionError {
    pub code: U32,
    // TODO: May send another U32
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinResult {
    pub pin_hash: RString,
    /// Not a "remember", probably
    /// Remeber seems to be client-side
    /// Client sends pin hash in auth req
    pub bool0: RBool,
    /// Maybe OK/CLOSE result
    pub bool1: RBool,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub unk0: U8,
    /// Equals to vec len?
    pub unk1: U16,
    // pub items: RVec<ItemDesc>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemDesc {
    pub slot: Op25,
    pub id: U32,
    pub count: U16,
    pub flags: U32,
    // TODO: Next content depends on flags
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatClient {
    pub id: U32,
    pub framerate: U32,
    pub unk0: U32,
    pub mb_ping: U32,
    pub unk: [U32; 2],
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatServer {
    pub id: U32,
    /// Probably server uptime, milliseconds
    pub time: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharacterMove {
    pub x: F32,
    pub y: F32,
    // TODO: May concat multiple packets
}

// [U8(9), U32(2347483652), U16(112), U16(8), "\0", U32(200), F32(38.25), F32(-27.75),
// U8(0), F32(-0.674698), F32(1), U32(2), U32(0), U32(200), F32(1.3), U16(0), U32(0),
// Bool(0), U32(0), U32(8)]
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    pub unk0: U8,
    pub id: U32,
    pub mob_id: U16,
    pub level: U16,
    pub unk1: RString, 
    pub hp: U32,
    pub x: F32,
    pub y: F32,
    pub unk2: U8,
    pub unk3: F32,
    pub unk4: F32,
    // TODO: Rest of data
}

// [U32(2347483652), F32(32.25), F32(55.75), U16(1331), U16(65), U16(24576)]
#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct EntityMove {
    pub id: U32,
    pub x: F32,
    pub y: F32,
    pub unk12: U16,
    #[debug("{:b}", flags.0)]
    pub flags: U16,
    pub unk16: U16,
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct EntityRemove {
    pub id: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub chat_id: Op21,
    pub text: RString,
    pub name: RString,
}

// Server: packet 82 (0x52) ; Length: 11 (0xb) bytes
// 0000:   01 00 08 4c  00 00 00 00  00 00 00                   ...L.......
// parsed: [U8(0), U64(76)]
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateBalance {
    pub currency: U8,
    pub balance: U64,
}

// Client: packet 146 (0x92) ; Length: 40 (0x28) bytes
// 0000:   04 8c c2 eb  8b 02 08 00  25 00 00 00  00 01 ff 05   ........%.......
// 0010:   5c eb 82 c1  05 6a 22 ce  42 05 82 19  92 c1 05 90   \....j".B.......
// 0020:   b2 bd 42 04  00 00 00 00                             ..B.....
// parsed: [U32(2347483788), U16(8), Op25([0, 0, 0, 0]), U8(255), F32(-16.364922),
// F32(103.067215), F32(-18.262455), F32(94.848755), U32(0)]
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attack {
    pub target_id: U32,
    pub unk4: U16,
    pub unk8: Op25,
    pub unk10: U8,
    pub unk11: [F32; 2],
    pub unk12: [F32; 2],
    pub unk13: U32,
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct PickupRequest {
    pub entity_id: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DealtDamage {
    pub target_id: U32,
    pub damager_id: U32,
    pub unk8: U8,
    pub unk9: U32,
    pub damage: U32,
    pub unk11: U32,
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct EntityDeath {
    pub id: U32,
}

// Server: packet 174 (0xae) ReceivedCurrency; Length: 29 (0x1d) bytes
// 0000:   01 05 08 0f  00 00 00 00  00 00 00 04  00 00 00 00   ................
// 0010:   04 55 06 00  00 02 01 00  04 00 00 00  00            .U...........
// parsed: [U8(5), U64(15), U32(0), U32(1621), U16(1), U32(0)]
// Server: packet 174 (0xae) ; Length: 12 (0xc) bytes
// 0000:   01 04 04 70  00 00 00 04  13 00 00 00                ...p........
// parsed: [U8(4), U32(112), U32(19)]
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrencyDiff {
    // TODO: Not only for receiving
    /// 4 for exp
    /// 8 for gold
    pub ctype: U8,
    pub mob_id: U32,
    pub value: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatUpdate {
    pub stat: U32,
    pub value: F32,
    pub unk: F32,
}

// --- --- --- --- --- --- --- --- --- --- --- --- --- --- move item request, slot #8 -> #20
// Client: packet 187 (0xbb) ; Length: 10 (0xa) bytes
// 0000:   25 08 00 02  02 25 14 00  02 02                      %....%....
// parsed: [Op25([8, 0, 2, 2]), Op25([20, 0, 2, 2])]
// --- --- --- --- --- --- --- --- --- --- --- --- --- --- slot #20, l-to-r, u-to-d
// Server: packet 190 (0xbe) ; Length: 10 (0xa) bytes
// 0000:   25 08 00 02  02 25 14 00  02 02                      %....%....
// parsed: [Op25([8, 0, 2, 2]), Op25([20, 0, 2, 2])]
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveItem {
    pub from: Op25,
    pub to: Op25,
}

// parsed: [U8(3), Op25([3, 0, 2, 2]), U32(1621), U16(1), U32(4096)]
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveItem {
    pub unk0: U8,
    pub slot: Op25,
    pub id: U32,
    pub quant: U16,
    /// Probably bitflags
    pub unk1: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuyItemRequest {
    pub id: U32,
    pub quant: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SellItemRequest {
    pub slot: Op25,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuyBack {
    pub index: U32,
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[debug("{:#?}", blob.hex_dump())]
pub struct CompressedData {
    #[br(parse_with = until_eof)]
    #[br(try_map = |v: Vec<u8>| zlib_decompress(&v))]
    pub blob: Vec<u8>,
    // TODO: Compress
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowEmotion {
    pub emo: RString,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatUpdateRequest {
    /// 0 - accuracy
    /// 35 - dexterity
    /// 156 - stamina
    pub stat: U32,
    pub value_add: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat2 {
    /// Probably, milliseconds
    pub client_uptime: U32,
}


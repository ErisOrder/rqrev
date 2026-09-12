//! Typical packet structure:
//! u16 size (incl. this field)
//! u16 type
//! variable data
//!
//! packet contents seems to be opcode-prefixed data types
//! 
//! strings and byte arrays are not distinguished easily,
//! they are represented as U16 len, variable data
//! 
//! # WARNING
//! Packets structure and type codes may differ in different game versions...
//! But at least they seem not to reuse type codes

use std::net::Ipv4Addr;

use binrw::{BinRead, BinResult, BinWrite, binrw, helpers::until_eof};
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
    /// Seems to be related to obfuscated? error reporting
    Packet16 = 0x16,

    /// Client -> Server
    /// DLC id
    SteamDlcInstalled = 0x25,

    /// Server -> Client
    /// Daily reward status
    DailyReward = 0x23,
    
    /// Client -> Server
    /// Issued when user presses "take reward" on char select screen
    TakeReward = 0x24,

    /// Client -> Server
    /// Steam microtransaction
    /// order id, authorized, 
    SteamMicroTxn = 0x28,

    /// Server -> Client
    /// Initializes player in world
    PlayerData = 0x33,

    /// Client -> Server
    EnterWorldRequest = 0x34,

    /// Server -> Client
    /// Inventory state
    Inventory = 0x38,
    
    /// Server -> Client
    EnterWorldResponse = 0x39,

    /// Client -> Server
    /// Name availability testing, single string
    TestCharNameReq = 0x3f,
    /// Server -> Client
    /// Name avail response, single u32
    TestCharNameResp = 0x40,

    /// Client -> Server
    /// Sent on character creation
    CreateCharacterReq = 0x41,

    /// Server -> Client
    /// Sent on successful character creation
    CreateCharacterRes = 0x43,
    
    /// Client -> Server
    HeartbeatClient = 0x46,
    /// Server -> Client
    HeartbeatServer = 0x47,
    
    /// Client -> Server
    SendChatMessage = 0x4D,
    
    /// Server -> Client
    ChatMessage = 0x4E,

    /// Server -> Client
    /// Sent when player balance (at least gold) updated
    UpdateBalance = 0x52,

    /// Server -> Client
    /// Sent when player enter game world
    SwitchLocation = 0x53,
    
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
    /// Sent when entity drops item
    EntityDrop = 0x5D,

    /// Server -> Client
    /// Sent when entity was removed (or disappear?)
    EntityRemove = 0x5E,
    
    /// Server -> Client
    /// Sent when entity was removed (or disappear?)
    EntityRemove2 = 0x5B,
    
    /// Client -> Server
    /// Move player character
    CharacterMove = 0x5F,

    /// Server -> Client
    /// Contains character location and camera parameters
    PosCamera = 0x64,
    
    /// Client -> Server
    /// Sent when player attacks entity, heals, takes food, etc
    UseAbility = 0x92,
    
    /// Client -> Server
    /// Sent when player wants to pickup dropped item
    /// Also used to activate various things, like chests
    PickupRequest = 0x95,

    /// Server -> Client
    /// Sent when entity attacks other entity or uses ability
    EntityAction = 0x9A,

    /// Server -> Client
    /// Sent when any player deals damage to entity
    DealtDamage = 0x9C,

    /// Server -> Client
    /// Not sure about it, but probably sent on some enity action like regen/hp update
    /// Probably has other ID on older version
    EntityActionPassive = 0xA0,

    /// Server -> Client
    EntityDeath = 0xA4,

    /// Server -> Client
    /// Sent when entity dies and player receives/gives currency, etc
    /// Seems to only be used to display lines in battle log
    BattleLog = 0xAE,

    // /// Server -> Client
    // /// Update quest info
    // QuestUpdate = 0xAB,

    /// Server -> Client
    /// Current level experience amount
    ExperienceAmount = 0xAF,

    /// Server -> Client
    /// Sent when character stat gets updated
    StatUpdate = 0xA7,

    // FIXME: Or not
    /// Server -> Client
    /// Sent to notify client about skill cooldown
    SkillCooldown = 0xB4,
    
    /// Client -> Server
    /// Sent when player moves item in inventory
    MoveItemRequst = 0xBB,

    /// Server -> Client
    /// Move item confirmation
    MoveItem = 0xBE,

    /// Server -> Client
    /// Sent when entity sets agro target (?)
    SetAgroTarget = 0xC0,

    /// Server -> Client
    /// Sent when player receives item
    ReceiveItem = 0xC1,
    
    /// Server -> Client
    /// May containt other player data
    PacketC5 = 0xC5,
    
    /// Client -> Server
    /// Sent when player increases character stat
    StatUpdateRequest = 0xCD,

    /// Client -> Server
    /// Sent when player clicks on dialog entry
    DialogEntryReq = 0xD4,

    /// Client -> Server
    /// Sent when player clicks on quest dialog entry
    DialogEntryCheckQuest = 0xD5,
    
    /// Server -> Client
    /// Response to DialogEntryReq
    /// Closes dialog window
    DialogClose = 0xD7,
    
    /// Server -> Client
    /// Response to DialogEntryReq
    DialogEntryRes = 0xD8,

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

    /// Seems to be same as CompressedData?
    /// Changed in newer game version?
    CompressedData2 = 0x12A,

    /// Server -> Client
    /// Sent when player starts action on some entity, like collecting resource
    StartEntityAction = 0x12F,
    
    /// Server -> Client
    /// Sent when player normally stops action on some entity, like collecting resource
    StopEntityAction = 0x130,
    
    /// Client -> Server
    /// Sent when player aborts current processing action
    AbortCurrentAction = 0x131,

    /// Server -> Client
    /// Sent when player aborts current processing action
    AbortEntityAction = 0x132,
    
    /// Server -> Client
    /// Contains PNG avatar of guild?
    GuildAvatar = 0x148,

    /// Client -> Server
    /// Sent when client wants to get friends online status
    CheckFriendsStatus = 0x162,

    /// Server -> Client
    /// Response to CheckFriendStatus, one per friend
    /// May be short or extended
    FriendStatus = 0x163,
    
    /// Server -> Client
    ShowEmotion = 0x194,

    /// Client -> Server
    ShowEmotionRequest = 0x196,

    /// Both directions
    /// Client initiates and server echoes some timestamp
    Heartbeat2 = 0x199,

    /// Both directions
    /// Client initiates and server echoes
    /// Contains milliseconds from client start 
    Heartbeat3 = 0x19C,

    /// Client -> Server
    ExitRequest = 0x1D4,

    /// Server -> Client
    ExitResponse = 0x1D5,

    /// Client -> Server
    /// Only sent from game world
    ExitRequestIngame = 0x1D7,

    /// Server -> Client
    /// Response to ExitRequestIngame
    /// Contains delay seconds
    ExitResponseIngame = 0x1D8,
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
    #[brw(magic(0x11u16))]
    CharList(CharList),
    #[brw(magic(0x12u16))]
    ServerVars(ServerVars),
    #[brw(magic(0x13u16))]
    Packet13(Packet13),
    #[brw(magic(0x16u16))]
    Packet16(Packet16),
    #[brw(magic(0x33u16))]
    PlayerData(PlayerData),
    #[brw(magic(0x34u16))]
    EnterWorldRequest(EnterWorldRequest),
    #[brw(magic(0x38u16))]
    Inventory(Inventory),
    #[brw(magic(0x39u16))]
    EnterWorldResponse(EnterWorldResponse),
    #[brw(magic(0x46u16))]
    HeartbeatClient(HeartbeatClient),
    #[brw(magic(0x47u16))]
    HeartbeatServer(HeartbeatServer),
    #[brw(magic(0x4Du16))]
    SendChatMessage(SendChatMessage),
    #[brw(magic(0x4Eu16))]
    ChatMessage(ChatMessage),
    #[brw(magic(0x52u16))]
    UpdateBalance(UpdateBalance),
    #[brw(magic(0x53u16))]
    SwitchLocation(SwitchLocation),
    #[brw(magic(0x56u16))]
    ConnectionClose2(),
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
    #[brw(magic(0x64u16))]
    PosCamera(PosCamera),
    #[brw(magic(0x92u16))]
    UseAbility(UseAbility),
    #[brw(magic(0x95u16))]
    PickupRequest(PickupRequest),
    #[brw(magic(0x9Au16))]
    EntityAction(EntityAction),
    #[brw(magic(0x9Cu16))]
    DealtDamage(DealtDamage),
    #[brw(magic(0xA0u16))]
    EntityActionPassive(EntityActionPassive),
    #[brw(magic(0xA4u16))]
    EntityDeath(EntityDeath),
    #[brw(magic(0xA7u16))]
    StatUpdate(StatUpdate),
    #[brw(magic(0xAEu16))]
    BattleLog(BattleLog),
    #[brw(magic(0xAFu16))]
    ExperienceAmount(ExperienceAmount),
    #[brw(magic(0xB4u16))]
    SkillCooldown(SkillCooldown),
    #[brw(magic(0xBBu16))]
    MoveItemRequest(MoveItem),
    #[brw(magic(0xBEu16))]
    MoveItemResponse(MoveItem),
    #[brw(magic(0xC1u16))]
    ReceiveItem(ReceiveItem),
    #[brw(magic(0xC5u16))]
    PacketC5(PacketC5),
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
    #[brw(magic(0x12Au16))]
    CompressedData2(CompressedData),
    #[brw(magic(0x196u16))]
    ShowEmotion(ShowEmotion),
    #[brw(magic(0x199u16))]
    Heartbeat2(Heartbeat2),
    #[brw(magic(0x19Cu16))]
    Heartbeat3(Heartbeat2),
    #[brw(magic(0x1D4u16))]
    ExitRequest(ExitRequest),
    #[brw(magic(0x1D5u16))]
    ExitResponse(ExitResponse),
    #[brw(magic(0x1D7u16))]
    ExitRequestIngame(ExitRequest),
    #[brw(magic(0x1D8u16))]
    ExitResponseIngame(ExitResponse),
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// time + 354 (game version number at time of capture)
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
    pub rdtsc: U64,
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
    pub servers: RVec<ServerDesc>,
    pub unk1: RVec<U16>,
    pub unk2: RVec<U16>,
    pub endpoints: RVec<EndpointDesc>,
    pub unk4: U32,
    pub unk5: RBool,
    pub unk6: U32,
    pub unixtime: U64,
    pub unk8: U32,
    pub mb_selected_server_id: U16,
    pub unk10: U64,
    pub unk11: RBytes,
    pub unk12: U32,
    // These 2 seems to be used as some session key
    pub xkey0: U32,
    pub xkey1: U64,
    // And rdtsc as validation?
    pub rdtsc_echo: U64,
    pub unk16: RString,
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct EndpointDesc {
    pub server_id: U16,
    #[br(map = |v: U32| core::net::Ipv4Addr::from_bits(v.0))]
    #[bw(map = |v| U32(v.to_bits()))]
    pub ip: Ipv4Addr,
    pub port: U16,
    pub unk3: U16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerDesc {
    pub id: U16,
    pub name: RString,
    pub unk1: U32,
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
    pub xkey0: U32,
    pub rdtsc: U64,
    pub xkey1: U64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharList {
    pub xkey0: U32,
    /// Same as ServerList.unk10
    pub unk1: U64,
    pub unk2: U32,
    pub some_flags: U32,
    /// Global variable in client
    pub unk4: U32,
    pub rdtsc_echo: U64,
    pub unk5: RString,
    
    pub unk6: U32,
    
    pub chars: RVec<CharacterSlot>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharacterSlot {
    pub id: U32,
    /// Slot is empty if id is 0
    #[br(if(id.0 != 0))]
    pub info: Option<CharacterInfo>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharacterInfo {
    /// 1 - warrior
    /// 2 - mage
    /// 3 - archer
    /// 4 - thief
    pub class: U16,
    /// 0 - male
    /// 1 - female
    pub sex: RBool,
    pub level: U16,
    pub unk3: U32,
    pub hp: U32,
    pub mp: U32,
    pub location_id: U32,
    pub body: BodyParam,
    pub name: RString,
    pub unk9: U8,
    pub unk10: U64,
    pub equip: RVec<ItemDesc>
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
pub struct Packet16 {
    pub rdtsc0: U64,
    pub unk1: U64,
    pub rdtsc1: U64,
    // Same as TimeSyncResponse.unk3
    pub unk2: U64,
    pub unk3: RString,  
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
#[derive(Clone, PartialEq, Eq, derive_more::Debug, Default)]
#[debug("[{:.2}, {:.2}]", x.0, y.0)]
pub struct Coords {
    pub x: F32,
    pub y: F32,
}

// parsed: [F32(0), F32(0), F32(0), F32(0), F32(0), F32(1), F32(0), F32(1), F32(0), F32(1), F32(0),
// F32(1), F32(0), F32(4), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0),
// F32(0), F32(0), F32(5), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0),
// F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0),
// F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0),
// F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0),
// F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0),
// F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0),
// F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0),
// F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(100), F32(0), F32(100), F32(0), F32(0.7),
// F32(0), F32(1), F32(0), F32(12), F32(0), F32(0), F32(0), F32(0), F32(0), F32(10), F32(0), F32(0),
// F32(0), F32(1), F32(0), F32(0), F32(0), F32(0), F32(7), F32(1), F32(0), F32(0), F32(0), F32(0),
// F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(0), F32(1), F32(0), F32(1), F32(0), F32(3),
// F32(0), F32(0), F32(0), F32(0), F32(0),
// U64(0), U16(0), U16(0), U64(0), F32(0), F32(30), U16(0),
// U16(0), U32(0), U32(0), U32(0), U16(36), U16(36), U16(36), U16(36), U16(27), U16(20), U16(20),
// U16(20), U16(20), U16(100), Op6C { len: 62, unk1: 0, data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
// 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }, U8(0), U16(0)]
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayerData {
    /// Seems to be ignored
    /// Entity tag?
    pub unk0: U8,
    pub id: U32,
    pub class: U16,
    pub level: U16,
    pub unk4: U8,
    pub unk5: U8,
    pub unk6: U8,
    pub name: RString,
    pub hp: U32,
    pub mp: U32,
    pub location_id: U32,
    pub coords: Coords,
    pub unk13: U8,
    pub rot: F32,
    pub unk15: RBool,
    pub alive: RBool,
    pub unk17: RBool,
    pub unk18: RBool,
    pub unk19: RBool,
    pub body: BodyParam,
    // Current state?
    pub hp2: U32,
    pub mp2: U32,
    pub movspeed: F32,
    pub unk24: U32,
    pub unk25: U32,
    pub unk26: U32,
    pub unk27: U32,
    pub unk28: U32,
    pub unk29: U8,
    pub unk30: U32,
    pub unk31: U32,
    pub unk32: RString,
    pub unk33: U64,
    pub unk34: U16,
    pub unk35: U16,
    pub unk36: RBool,
    pub unk37: RString,
    pub unk38: U32,

    pub effects: RVec<CameraEffect>,
    
    pub unk39: Op13,
    /// Exp on this level
    pub current_exp: U32,
    pub unk41: U32,
    pub unk42: U16,
    pub stats: RVec<F32>,
    // Apparently has the same size
    #[br(count = stats.data.len())]
    pub stats2: Vec<F32>,

    pub unk45: U64,
    pub talents: RVec<U16>,
    pub unk47: RVec<U16>,
    pub unk48: U64,
    pub unk49: F32,
    pub unk50: F32,
    pub unk51: U16,
    pub unk52: U16,
    pub unk53: U32,
    pub unk54: U32,
    pub unk55: U32,
    pub unk56: [U16; 4],
    pub unk57: U16,
    pub unk58: [U16; 4],
    pub unk59: U16,
    pub unk60: CurrencyData,
    pub unk61: U8,   
    pub ach_data: RZlib,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterWorldRequest {
    pub char_idx: U8,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterWorldResponse {
    pub unk: U16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub unk0: U8,
    /// Equals to vec len?
    pub unk1: U16,
    pub items: RVec<ItemDesc>,
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct ItemDesc {
    pub slot: InvSlot,
    pub id: U32,
    pub count: U16,
    #[debug("{:#x}", flags.0)]
    pub flags: U32,

    // FIXME: Something wrong here
    // #[br(if(flags.0 & 0x1000 != 0))]
    #[br(default)]
    pub unk5: Option<U32>,
    
    #[br(if(flags.0 & 0x2000 != 0))]
    pub unk6: Option<U64>,

    #[br(if(flags.0 & 0x8000 != 0))]
    pub ext: Option<ItemDescExt>,
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct ItemDescExt {
    /// 1992 is special
    pub unk0: U32,
    pub unk1: U32,
    pub unk2: U32,
    pub unk3: U16,
    pub unk4: U8,
    pub unk5: U8,
    pub unk6: U32,
    pub unk7: U8,
    pub unk8: U32,
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
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct CharacterMove {
    pub coords: Coords,
    /// Flags:
    /// 0x20 - stop
    /// 0x200 - ?
    /// 0x2 - cursor is being held
    /// 0x1 - target changed
    #[debug("{:#x}", flags.0)]
    pub flags: U16,
    /// Seems to be move direction from 0 to 65535, where 0 is lower-mid
    pub direction: U16, 
    /// Another direction, always sent when char starts to move
    #[br(if(flags.0 & 0x200 != 0))]
    pub dir2: Option<U8>,
    #[br(if(flags.0 & 0x200 != 0))]
    pub unk4: Option<U8>,
    // TODO: May concat multiple packets
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    pub tag: U8,
    #[br(args(tag.0))]
    pub kind: EntityKind,
}

#[binrw]
#[brw(little)]
#[brw(import(tag: u8))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityKind {
    #[br(pre_assert(tag == 9))]
    Mob(MobEntity),
    #[br(pre_assert(tag == 8))]
    Player(PlayerEntity),
    UnknownOrFailed,
}

// Server: packet 0x5A (90) EntityAdd
// parsed: Entity(Entity { unk0: U8(9), id: U32(2347483658), mob_id: U16(31), level: U16(4), unk1: "\0", hp: U32(120), x: F32(-37.97446), y: F32(102.5613), unk2: U8(0), unk3: F32(-0.6671703), unk4: F32(1.0) })
// left: Length: 40 (0x28) bytes
// 0000:   04 03 00 00  00 04 00 00  00 00 04 78  00 00 00 05   ...........x....
// 0010:   cd cc bc 40  02 00 00 04  00 00 00 00  03 00 04 00   ...@............
// 0020:   00 00 00 04  08 00 00 00                             ........
// parsed: [U32(3), U32(0), U32(120), F32(5.9), U16(0), U32(0), Bool(0), U32(0), U32(8)]
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobEntity {
    pub id: U32,
    pub mob_id: U16,
    pub level: U16,
    pub custom_name: RString, 
    pub hp: U32,
    pub coords: Coords,
    pub unk2: U8,
    pub unk3: F32,
    pub scale: F32,
    pub unk5: U32,
    pub unk6: U32,
    pub max_hp: U32,
    pub unk8: F32,
    pub unk9: U16,
    pub unk10: U32,
    pub unk11: RBool,
    pub unk12: U32,
    pub unk13: U32,
}


// 
#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct PlayerEntity {
    pub id: U32,
    pub class: U16,
    pub level: U16,
    pub unk4: U8,
    pub unk5: U8,
    pub unk6: U8,
    pub name: RString,
    pub hp: U32,
    pub mp: U32,
    pub location_id: U32,
    pub coords: Coords,
    pub unk13: U8,
    pub rot: F32,
    pub unk15: RBool,
    pub alive: RBool,
    pub unk17: RBool,
    pub unk18: RBool,
    pub unk19: RBool,
    pub body: BodyParam,
    // Not main, main is in the stats
    pub max_hp: U32,
    pub max_mp: U32,
    pub movspeed: F32,
    pub unk24: U32,
    pub unk25: U32,
    pub unk26: U32,
    pub unk27: U32,
    pub unk28: U32,
    pub unk29: U8,
    // At least to here matches
    pub unk30: U32,
    pub unk31: U32,
    pub unk32: RString,
    pub unk33: U64,
    pub unk34: U16,
    pub unk35: U16,
    pub unk36: RBool,
    pub unk37: RString,
    pub unk38: U32,

    pub effects: RVec<CameraEffect>,
    
    pub unk39: Op13,
    /// Exp on this level
    pub current_exp: U32,
    pub unk41: U32,
    pub unk42: U16,
    pub stats: RVec<F32>,
    // Apparently has the same size
    #[br(count = stats.data.len())]
    pub stats2: Vec<F32>,

    pub unk45: U64,
    pub talents: RVec<U16>,
    pub unk47: RVec<U16>,
    pub unk48: U64,
    pub unk49: F32,
    pub unk50: F32,
    pub unk51: U16,
    pub unk52: U16,
    pub unk53: U32,
    pub unk54: U32,
    pub unk55: U32,
    pub unk56: [U16; 4],
    pub unk57: U16,
    pub unk58: [U16; 4],
    pub unk59: U16,
    pub unk60: CurrencyData,
    pub unk61: U8,   
    pub ach_data: RZlib,
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct EntityMove {
    pub id: U32,
    pub coords: Coords,
    pub unk12: U16,
    #[debug("{:#x}", flags.0)]
    pub flags: U16,
    pub direction: U16,
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
pub struct SendChatMessage {
    pub chat_id: Op21,
    pub text: RString,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub chat_id: Op21,
    pub text: RString,
    pub name: RString,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateBalance {
    pub currency: U8,
    pub balance: U64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchLocation {
    pub location_id: U32,
    pub unk1: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosCamera {
    pub unk0: U32,
    pub coords: Coords,
    pub rot: F32,
    pub unk4: U8,
    /// Need for movement to work
    pub movspeed: F32,
    
    pub effects: RVec<CameraEffect>,    
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraEffect {
    pub id: U16,
    pub player_id: U32,
    // MB related to duration
    pub unk2: U32,
    pub v1: Prefixed,
    pub v2: Prefixed
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[debug("{:?}", value)]
pub struct Prefixed {
    #[br(temp)]
    #[bw(calc = U8(value.prefix()))]
    pub prefix: U8,
    #[br(args(prefix.0))]
    pub value: PrefixedValue,
}

#[binrw]
#[brw(little)]
#[brw(import(prefix: u8))]
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefixedValue {
    #[br(pre_assert(prefix == 0))]
    Empty,
    #[br(pre_assert(prefix == 1))]
    U8(U8),
    #[br(pre_assert(prefix == 2))]
    U16(U16),
    #[br(pre_assert(prefix == 3))]
    F32(F32),
    #[br(pre_assert(prefix == 0xF))]
    F32x2([F32; 2]),
}

impl PrefixedValue {
    pub fn prefix(&self) -> u8 {
        match self {
            PrefixedValue::Empty => 0,
            PrefixedValue::U8(_) => 1,
            PrefixedValue::U16(_) => 2,
            PrefixedValue::F32(_) => 3,
            PrefixedValue::F32x2(_) => 0xF,
        }
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseAbility {
    pub target_id: U32,
    pub skill_id: U16,
    pub used_item: InvSlot,
    pub unk10: U8,
    pub pos0: Coords,
    pub pos1: Coords,
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
pub struct EntityAction {
    pub entity_id: U32,
    pub skill_id: U16,
    /// Radius/point?
    pub dtype: U16,
    pub param: F32,
    #[brw(if(dtype.0 == 3))]
    pub pos: Option<Coords>,
    pub target_id: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DealtDamage {
    pub target_id: U32,
    pub damager_id: U32,
    pub unk8: U8,
    pub skill_id: U32,
    pub damage: U32,
    pub unk11: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityActionPassive {
    pub entity_id: U32,
    pub kind: U16,
    #[brw(if(kind.0 == 3))]
    pub unk3: Option<U32>,
    #[brw(if(kind.0 == 6))]
    pub unk6: Option<U32>,
    #[brw(if(kind.0 == 8))]
    pub target_id: Option<U32>,
}

#[binrw]
#[brw(little)]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub struct EntityDeath {
    pub id: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BattleLog {
    /// 4 - receive exp from mob
    /// 8 - receive gold
    pub tag: U8,
    // These are for tag 4
    // pub mob_id: U32,
    // pub value: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatUpdate {
    pub stat: U32,
    pub value: F32,
    pub unk: F32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExperienceAmount {
    pub value: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillCooldown {
    pub seconds: F32,
    pub skill_id: U16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveItem {
    pub from: InvSlot,
    pub to: InvSlot,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveItem {
    pub unk0: U8,
    pub item: ItemDesc,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketC5 {
    pub unk0: RZlib,
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
    pub slot: InvSlot,
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

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitRequest {
    /// Exit type:
    /// 0 - to character selection
    /// 1 - to main menu
    /// 2 - exit game
    pub code: U32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitResponse {
    /// Seconds
    pub delay: U32,
}


use std::io::{Cursor, Read, Seek, SeekFrom};

use binrw::{BinRead, BinResult, BinWrite, NullString, binread, binrw, binwrite, meta::ReadEndian};
use pretty_hex::{HexConfig, PrettyHex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x01u8)]
pub struct U8(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x02u8)]
pub struct U16(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x03u8)]
pub struct RBool(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x04u8)]
pub struct U32(pub u32);

#[derive(Debug, Clone, Copy, PartialEq)]
#[binrw]
#[brw(little, magic = 0x05u8)]
pub struct F32(pub f32);
impl Eq for F32 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x08u8)]
pub struct U64(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x13u8)]
pub struct Op13([u16; 4]);

/// u32 haircolor | u32 skin | u16 unk | u16 face | u16 unk | u16 unk
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x1Du8)]
pub struct BodyParam {
    pub haircolor: u16,
    pub unk1: u16,
    pub skin: u16,
    pub unk3: u16,
    pub unk4: u16,
    pub face: u16,
    pub unk6: u16,
    pub unk7: u16,
}

#[derive(derive_more::Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x21u8)]
#[debug("{:#x}", _0)]
pub struct Op21(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x25u8)]
pub struct InvSlot{
    pub idx: u8,
    /// Part of u16 index?
    pub unk1: u8, 
    /// Inventory tab
    pub tab: u8,
    /// Inventory
    /// 0 - trash
    /// 1 - equipment
    /// 2 - main inventory
    pub inv: u8, 
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x36u8)]
pub struct Op36(pub u32, pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[binrw]
#[brw(little, magic = 0x3Bu8)]
pub struct Op3B(pub [u32; 4]);

/// Contains array of currency balances
/// 0 - gold
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little, magic = 0x6Cu8)]
pub struct CurrencyData {
    pub data: [u16; 36]
}

#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct RBytes {
    #[bw(calc = U16(data.len() as u16))]
    #[br(temp)]
    len: U16,
    #[br(count = len.0)]
    pub data: Vec<u8>
}

impl<T: AsRef<[u8]>> From<T> for RBytes {
    fn from(value: T) -> Self {
        RBytes { data: Vec::from(value.as_ref()) }
    }
}

#[binrw]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[brw(little)]
#[debug("{:#?}", self.data.hex_dump())]
pub struct RZlib {
    #[bw(calc = U16(data.len() as u16))]
    #[br(temp)]
    len: U16,
    #[br(count = len.0)]
    /// u16 uncompressed size is probably prepended 
    /// `yasli`-encoded?
    /// 0xB1A4C17F - magic
    #[br(try_map = |v: Vec<u8>| if v.len() == 0 {
        Ok(vec![])
    } else {
        zlib_decompress(&v[2..])
    })]
    // TODO: Compress
    pub data: Vec<u8>
}

#[binrw]
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
#[brw(little)]
#[debug("{:?}", self.data)]
pub struct RString {
    #[bw(calc = U16(data.len() as u16))]
    #[br(temp)]
    len: U16,
    #[br(count = len.0)]
    #[br(try_map = |v: Vec<u8>| String::from_utf8(v))]
    #[bw(map = |v| v.as_bytes())]
    pub data: String,
}

impl RString {
    pub fn empty() -> Self {
        Self {
            data: String::from("\0")
        }
    }
}

impl<T: ToString> From<T> for RString {
    fn from(value: T) -> Self {
        let mut s = value.to_string();
        s.push('\0');
        RString {
            data: s,
        }
    }
}

#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[brw(little)]
pub struct RVec<T>
where T: for<'a> BinRead<Args<'a> = ()> + for<'a> BinWrite<Args<'a> = ()> + 'static
{
    #[bw(calc = U16(data.len() as u16))]
    #[br(temp)]
    len: U16,
    
    #[br(count = len.0)]
    pub data: Vec<T>,
}

impl<T> From<Vec<T>> for RVec<T>
where T: for<'a> BinRead<Args<'a> = ()> + for<'a> BinWrite<Args<'a> = ()> + 'static
{
    fn from(value: Vec<T>) -> Self {
        Self { data: value }
    }
} 

#[derive(derive_more::Debug, Clone, PartialEq, Eq, derive_more::TryUnwrap)]
#[binread]
#[br(little)]
pub enum DataElement {
    #[debug("U8({})", _0.0)]
    U8(U8),
    #[debug("U16({})", _0.0)]
    U16(U16),
    #[debug("Bool({})", _0.0)]
    Bool(RBool),
    #[debug("U32({})", _0.0)]
    U32(U32),
    #[debug("U64({})", _0.0)]
    U64(U64),
    #[debug("F32({})", _0.0)]
    F32(F32),
    #[debug("{:?}", _0)]
    Op13(Op13),
    #[debug("{:?}", _0)]
    Op1D(BodyParam),
    #[debug("{:?}", _0)]
    Op21(Op21),
    #[debug("{:?}", _0)]
    Op25(InvSlot),
    #[debug("{:?}", _0)]
    Op36(Op36),
    #[debug("{:?}", _0)]
    Op3B(Op3B),
    #[debug("{:?}", _0)]
    CurrencyData(CurrencyData),

    // String/bytes read condition: EOF or next element is valid
    #[br(pre_assert(false))]
    #[debug("{:?}", _0)]
    String(#[br(ignore)] String),
    #[br(pre_assert(false))]
    #[debug("Bytes({})", _0.hex_conf({
        let mut cfg = HexConfig::simple();
        cfg.group = 0;
        cfg.chunk = 0;
        cfg
    }))]
    Bytes(#[br(ignore)] Vec<u8>),
}

pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, flate2::DecompressError> {
    let mut out = Vec::with_capacity(131072);
    let s = flate2::Decompress::new(true)
        .decompress_vec(data, &mut out, flate2::FlushDecompress::Finish)?;
    println!("decompress {} bytes: {s:?}", data.len());
    Ok(out)
}

impl DataElement {
    pub fn read_guess(mut reader: impl Seek + Read) -> binrw::BinResult<Self> {
        let bpos = reader.stream_position()?;
        let elem = Self::read(&mut reader)?;
        match elem {
            DataElement::U16(U16(d)) => {
                'blk: {
                    if d == 0 {
                        break 'blk;
                    }
                    
                    // 1. Try to read as bytes
                    let mut bytes = vec![0; d as usize];
                    
                    match reader.read_exact(&mut bytes) {
                        // Success: check if next element is readable
                        Ok(_) => {                           
                            let bpos = reader.stream_position()?;
                            let eof = bpos == reader.stream_len()?;
                            
                            let next = Self::read(&mut reader);
                            reader.seek(SeekFrom::Start(bpos))?;
                            
                            // If opcode or EOF, we're probably good
                            if next.is_ok() || eof {
                                // 2. Try to decode as string
                                match String::from_utf8(bytes) {
                                    Ok(s) => {
                                        return Ok(DataElement::String(s))
                                    },
                                    Err(e) => {
                                        return Ok(DataElement::Bytes(e.into_bytes()))
                                    },
                                }
                                
                            } else {
                                // If not, we probably missed
                                break 'blk;
                            }
                        },
                        // Fallback
                        Err(_) => break 'blk,
                    };
                };

                // 3. Fallback to plain U16
                reader.seek(SeekFrom::Start(bpos + 3))?;
                Ok(DataElement::U16(U16(d)))             
            },
            other => Ok(other)
        }
    }
}

pub fn read_guess_all(mut reader: impl Seek + Read) -> binrw::BinResult<Vec<DataElement>> {
    let mut out = vec![];
    loop {
        if reader.stream_position()? == reader.stream_len()? {
            break;
        }
        
        let next = DataElement::read_guess(&mut reader)?;

        // println!("{next:?}; pos:{:?} {:?}", reader.stream_position(), reader.stream_len());
        
        out.push(next);
    }

    Ok(out)
}

impl<T> BinReadChecked for T where T: for<'a> BinRead<Args<'a> = ()> + ReadEndian {}
pub trait BinReadChecked: for<'a> BinRead<Args<'a> = ()> + ReadEndian {
    fn read_partial(data: &[u8]) -> BinResult<(Self, usize)> {
        let mut curs = std::io::Cursor::new(data);
        let p = Self::read(&mut curs)?;
        Ok((p, curs.position() as usize))
    }
    
    fn read_checked(data: &[u8]) -> BinResult<Self> {
        let mut curs = std::io::Cursor::new(data);
        let p = Self::read(&mut curs)?;
        if curs.position() as usize == data.len() {
            Ok(p)
        } else {
            Err(binrw::Error::Custom { pos: curs.position(), err: Box::new("has data left") })
        }
    }
}

#[test]
pub fn packet_x() {
    let hex = hex_literal::hex!("
        03 01 02 02  00 02 25 00  35 62 30 36  38 36 36 31
        2d 31 62 64  30 2d 31 31  66 31 2d 38  38 66 31 2d
        66 61 31 36  33 65 65 34  63 34 63 35  00 02 25 00
        35 62 30 36  39 30 37 38  2d 31 62 64  30 2d 31 31
        66 31 2d 38  38 66 31 2d  66 61 31 36  33 65 65 34
        63 34 63 35  00 04 5f ed  ae 69 04 94  06 00 00 02
        1e 00 04 00  00 04 00 02  25 00 39 61  62 33 31 38
        36 36 2d 31  63 66 31 2d  31 31 66 31  2d 38 38 66
        31 2d 66 61  31 36 33 65  65 34 63 34  63 35 00 02
        25 00 39 61  62 33 31 64  37 39 2d 31  63 66 31 2d
        31 31 66 31  2d 38 38 66  31 2d 66 61  31 36 33 65
        65 34 63 34  63 35 00 04  a7 d2 b0 69  04 7e 0d 00
        00 02 0a 00  04 00 00 04  00 03 01                
    ");

    let v = read_guess_all(Cursor::new(hex)).unwrap();
}

#[test]
pub fn packet_02() {
    let hex = hex_literal::hex!("
        02 0a 00 02  04 00 02 0d  00 d0 93 d0  b5 d0 bb d0
        b8 d0 be d1  81 00 04 02  00 00 00 02  05 00 02 0f
        00 49 67 6e  69 73 20 28  45 75 72 6f  70 65 29 00
        04 05 00 00  00 02 06 00  02 10 00 41  7a 74 65 63
        20 28 41 6d  65 72 69 63  61 29 00 04  02 00 00 00
        02 07 00 02  10 00 4f 72  74 6f 73 20  28 41 6d 65
        72 69 63 61  29 00 04 01  00 00 00 02  08 00 02 0d
        00 41 73 74  75 73 20 28  41 73 69 61  29 00 04 03
        00 00 00 02  09 00 02 0a  00 53 6f 6c  75 73 5f 6f
        6c 64 00 04  03 00 00 00  02 0a 00 02  11 00 d0 a4
        d0 b5 d0 bd  d0 b8 d0 ba  d1 81 5f 6f  6c 64 00 04
        02 00 00 00  02 0b 00 02  06 00 53 6f  6c 75 73 00
        04 03 00 00  00 02 0c 00  02 0d 00 d0  a4 d0 b5 d0
        bd d0 b8 d0  ba d1 81 00  04 01 00 00  00 02 33 00
        02 0f 00 50  79 72 6f 73  20 28 45 75  72 6f 70 65
        29 00 04 04  00 00 00 02  0a 00 02 04  00 02 14 00
        02 05 00 02  00 00 02 06  00 02 00 00  02 07 00 02
        00 00 02 08  00 02 00 00  02 09 00 02  00 00 02 0a
        00 02 00 00  02 0b 00 02  00 00 02 0c  00 02 1c 00
        02 33 00 02  00 00 02 02  00 02 04 00  04 25 09 35
        c1 02 9e 10  02 2f 00 02  0c 00 04 25  09 35 5e 02
        9e 10 02 4d  00 04 00 00  00 00 03 00  04 00 00 00
        00 08 53 a3  b2 69 00 00  00 00 04 b9  a4 8e 22 02
        04 00 08 f4  8f b2 69 00  00 00 00 02  01 00 02 04
        00 02 01 00  04 e4 6b 99  00 08 32 11  fb 4f 07 af
        00 00 08 aa  f6 0e 83 e9  04 00 00 02  01 00 00   
    ");

    let v = crate::protocol::ServerList::read_partial(&hex).unwrap();
    dbg!(v);
    // let v = read_guess_all(Cursor::new(hex)).unwrap();
}
#[test]
pub fn packet_4e() {
    let hex = hex_literal::hex!("
        21 00 28 50  00 02 0f 00  34 2d 38 d0  ba d0 b8 20
        2b 32 d0 94  d0 94 00 02  19 00 d0 95  d0 bb d0 b8
        d0 b7 d0 b0  d0 b2 d0 b5  d1 82 d0 be  d1 87 d0 ba
        d0 b0 00                                          
    ");

    let v = crate::protocol::ChatMessage::read_partial(&hex).unwrap();
    dbg!(v);
    // let v = read_guess_all(Cursor::new(hex)).unwrap();
}

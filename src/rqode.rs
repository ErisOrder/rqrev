use std::fmt::Display;
use std::io::{Cursor, ErrorKind, Read, Seek};

use derive_more::TryUnwrapError;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use pretty_hex::{HexConfig, PrettyHex};

pub struct RQParser<T> {
    data: Cursor<T>
}

#[derive(thiserror::Error)]
pub enum ParseError {
    #[error("unerlying io: {0}")]
    IO(#[from] std::io::Error),
    #[error("unknown type opcode: {0} ({0:#x}) at pos {1}")]
    UnknownOpcode(u8, usize),
    #[error("invalid start for byte array: {0:?}")]
    InvalidByteArrayStart(DataElement),
    #[error("custom: {0}")]
    Custom(String),
    #[error("there were trailing bytes after deserialization")]
    TrailingBytes,
    // #[error("expected {expected:?}, parsed {parsed:?}")]
    // InvalidElement {
    //     expected: DataOpcode,
    //     parsed: DataElement,
    // }
    #[error("parsed invalid element: {0}")]
    InvalidElement(#[from] TryUnwrapError<DataElement>),
    #[error("utf8 validation error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl std::fmt::Debug for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

#[derive(TryFromPrimitive, IntoPrimitive, Clone, Copy, Debug)]
#[repr(u8)]
pub enum DataOpcode {
    /// Single u8 byte
    U8 =   0x01,
    /// u16 len, usually comes before variable data (excl. len)
    U16 =  0x02,
    /// Single u8 byte (bool?)
    Bool = 0x03,
    /// Single u32
    U32 =  0x04,
    /// Signle u64
    U64 =  0x08,
    
    /// Single u32
    Op05 = 0x05,
    /// Tuple (u32, u16)
    Op36 = 0x36,
    /// Single u32, maybe chat id
    Op21 = 0x21,
    
    // If first u8 == 0, no data; option?
    // Op0E = 0x0E,
    // Op0C = 0x0C,
    // u32 val?
    // Op25 = 0x25,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::TryUnwrap)]
pub enum DataElement {
    U8(u8),
    U16(u16),
    Bool(u8),
    U32(u32),
    U64(u64),
    Op05(u32),
    Op21(u32),
    Op36(u32, u16),
}

#[derive(Clone, serde::Serialize, PartialEq, Eq, derive_more::Debug)]
pub enum DataElementComposite {
    U8(u8),
    Bool(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    #[debug("Bytes({})", _0.hex_conf({
        let mut cfg = HexConfig::simple();
        cfg.group = 0;
        cfg.chunk = 0;
        cfg
    }))]
    Bytes(Vec<u8>),
    String(String),
    Op05(u32),
    Op21(u32),
    Op36(u32, u16),
}

impl From<DataElement> for DataElementComposite {
    fn from(value: DataElement) -> Self {
        match value {
            DataElement::U8(d) => DataElementComposite::U8(d),
            DataElement::U16(d) => DataElementComposite::U16(d),
            DataElement::Bool(d) => DataElementComposite::Bool(d),
            DataElement::U32(d) => DataElementComposite::U32(d),
            DataElement::U64(d) => DataElementComposite::U64(d),
            DataElement::Op21(d) => DataElementComposite::Op21(d),
            DataElement::Op36(a, b) => DataElementComposite::Op36(a, b),
            DataElement::Op05(d) => DataElementComposite::Op05(d),
        }
    }
}

pub type ParseResult<T> = Result<T, ParseError>;

impl<T: AsRef<[u8]>> RQParser<T> {
    pub fn new(data: T) -> Self {
        Self { data: Cursor::new(data) }
    } 
    
    // Primitive read methods
    pub fn read_u8(&mut self) -> ParseResult<u8> {
        let mut res = [0];
        self.data.read_exact(&mut res)?;
        Ok(res[0])
    }
    
    pub fn read_u16(&mut self) -> ParseResult<u16> {
        let mut res = [0u16];
        self.data.read_exact(bytemuck::cast_slice_mut(&mut res))?;
        Ok(res[0])
    }
    
    pub fn read_u32(&mut self) -> ParseResult<u32> {
        let mut res = [0u32];
        self.data.read_exact(bytemuck::cast_slice_mut(&mut res))?;
        Ok(res[0])
    }
    
    pub fn read_u64(&mut self) -> ParseResult<u64> {
        let mut res = [0u64];
        self.data.read_exact(bytemuck::cast_slice_mut(&mut res))?;
        Ok(res[0])
    }
    
    pub fn read_bytes(&mut self, buf: &mut [u8]) -> Result<(), ParseError> {
        self.data.read_exact(buf)?;
        Ok(())
    }

    pub fn pos(&mut self) -> usize {
        self.data.position() as usize
    }
    
    // Composed read

    /// Read next opcode-prefixed element
    pub fn read_next_element(&mut self) -> ParseResult<DataElement> {
        let opcode = self.read_u8()?;
        let opcode = DataOpcode::try_from_primitive(opcode)
            .map_err(|_| ParseError::UnknownOpcode(opcode, self.pos()))?;

        let res = match opcode {
            DataOpcode::U8 => DataElement::U8(self.read_u8()?),
            DataOpcode::U16 => DataElement::U16(self.read_u16()?),
            DataOpcode::Bool => DataElement::Bool(self.read_u8()?),
            DataOpcode::U32 => DataElement::U32(self.read_u32()?),
            DataOpcode::U64 => DataElement::U64(self.read_u64()?),
            DataOpcode::Op05 => DataElement::Op05(self.read_u32()?),
            DataOpcode::Op21 => DataElement::Op21(self.read_u32()?),
            DataOpcode::Op36 => DataElement::Op36(
                self.read_u32()?,
                self.read_u16()?
            ),
        };

        Ok(res)
    }

    /// Try to read next element as byte array
    pub fn read_byte_array(&mut self) -> ParseResult<Vec<u8>> {
        let start = self.read_next_element()?;
        let DataElement::U16(len) = start else {
            return Err(ParseError::InvalidByteArrayStart(start));
        };

        let mut data = vec![0u8; len as usize];
        self.read_bytes(&mut data)?;

        Ok(data)
    }
    
    /// Try to read next element as byte array and convert to string
    pub fn read_string(&mut self) -> ParseResult<String> {
        let data = self.read_byte_array()?;
        let mut s = String::from_utf8(data)?;

        if s.ends_with('\0') {
            s.pop();
        }

        Ok(s)
    }

    pub fn has_data(&self) -> bool {
        self.data.position() < self.data.get_ref().as_ref().len() as u64
    }

    pub fn read_guess(&mut self) -> ParseResult<DataElementComposite> {
        let bpos = self.data.position();
        match self.read_next_element()? {
            // Try to read as byte array or string
            DataElement::U16(d) => {
                'blk: {
                    if d == 0 {
                        break 'blk;
                    }
                    
                    // 1. Try to read as bytes
                    self.data.set_position(bpos);
                    match self.read_byte_array() {
                        // Success: check if next byte is opcode
                        Ok(b) => {                           
                            let bpos = self.data.position();
                            let next = self.read_u8();
                            self.data.set_position(bpos);
                            
                            // If opcode or EOF, we're probably good
                            if next.is_ok_and(|op| DataOpcode::try_from_primitive(op).is_ok())
                                || !self.has_data()
                            {
                                // 2. Try to decode as string
                                match String::from_utf8(b) {
                                    Ok(mut s) => {
                                        // Trim last zero
                                        if s.ends_with('\0') {
                                            s.pop();
                                        }
                                        return Ok(DataElementComposite::String(s))
                                    },
                                    Err(e) => {
                                        return Ok(DataElementComposite::Bytes(e.into_bytes()))
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
                self.data.set_position(bpos + 3);
                Ok(DataElementComposite::U16(d))
            },
            other => Ok(other.into()),
        }
    }

    pub fn read_guess_all(&mut self) -> ParseResult<Vec<DataElementComposite>> {
        let mut out = vec![];
        while self.has_data() {
            let next = self.read_guess()?;
            // println!("{next:?}; pos:{}", self.data.position());
            out.push(next);
        }

        Ok(out)
    }
}


// use pretty_hex::{HexConfig, PrettyHex};
// use serde::Deserialize;
// use serde::de::{
//     self, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
//     VariantAccess, Visitor,
// };

// impl serde::de::Error for ParseError {
//     fn custom<T>(msg:T) -> Self where T: Display {
//         Self::Custom(msg.to_string())
//     }
// }


// pub struct Deserializer<'de> {
//     input: RQParser<&'de [u8]>,
// }

// impl<'de> Deserializer<'de> {
//     pub fn from_slice(input: &'de [u8]) -> Self {
//         Deserializer { input: RQParser::new(input) }
//     }
// }

// pub fn from_slice<'a, T>(s: &'a [u8]) -> ParseResult<T>
// where
//     T: Deserialize<'a>,
// {
//     let mut deserializer = Deserializer::from_slice(s);
//     let t = T::deserialize(&mut deserializer)?;
//     if !deserializer.input.has_data() {
//         Ok(t)
//     } else {
//         Err(ParseError::TrailingBytes)
//     }
// }

// impl<'de, 'a> de::Deserializer<'de> for &'a mut Deserializer<'de> {
//     type Error = ParseError;

//     // Look at the input data to decide what Serde data model type to
//     // deserialize as. Not all data formats are able to support this operation.
//     // Formats that support `deserialize_any` are known as self-describing.
//     fn deserialize_any<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let x = self.input.read_guess()?;
//         match x {
//             DataElementComposite::U8(d) => visitor.visit_u8(d),
//             DataElementComposite::Bool(d) => visitor.visit_bool(d != 0),
//             DataElementComposite::U16(d) => visitor.visit_u16(d),
//             DataElementComposite::U32(d) => visitor.visit_u32(d),
//             DataElementComposite::U64(d) => visitor.visit_u64(d),
//             DataElementComposite::Bytes(d) => visitor.visit_byte_buf(d),
//             DataElementComposite::String(d) => visitor.visit_string(d),
//             DataElementComposite::Op36(..) => unimplemented!()
//         }
//     }

//     fn deserialize_bool<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         // TODO: Opcode 3?
//         let du8 = self.input.read_next_element()?.try_unwrap_bool()?;
//         visitor.visit_bool(du8 != 0)
//     }

//     fn deserialize_i8<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let du8 = self.input.read_next_element()?.try_unwrap_u_8()?;
//         visitor.visit_i8(du8 as i8)
//     }

//     fn deserialize_i16<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let elem = self.input.read_next_element()?.try_unwrap_u_16()?;
//         visitor.visit_i16(elem as i16)
//     }

//     fn deserialize_i32<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let elem = self.input.read_next_element()?.try_unwrap_u_32()?;
//         visitor.visit_i32(elem as i32)
//     }

//     fn deserialize_i64<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let elem = self.input.read_next_element()?.try_unwrap_u_64()?;
//         visitor.visit_i64(elem as i64)
//     }

//     fn deserialize_u8<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let elem = self.input.read_next_element()?.try_unwrap_u_8()?;
//         visitor.visit_u8(elem)
//     }

//     fn deserialize_u16<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let elem = self.input.read_next_element()?.try_unwrap_u_16()?;
//         visitor.visit_u16(elem)
//     }

//     fn deserialize_u32<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let elem = self.input.read_next_element()?.try_unwrap_u_32()?;
//         visitor.visit_u32(elem)
//     }

//     fn deserialize_u64<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let elem = self.input.read_next_element()?.try_unwrap_u_64()?;
//         visitor.visit_u64(elem)
//     }

//     // Float parsing is stupidly hard.
//     fn deserialize_f32<V>(self, _visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         unimplemented!()
//     }

//     // Float parsing is stupidly hard.
//     fn deserialize_f64<V>(self, _visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         unimplemented!()
//     }

//     fn deserialize_char<V>(self, _visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         unimplemented!()
//     }

//     // Refer to the "Understanding deserializer lifetimes" page for information
//     // about the three deserialization flavors of strings in Serde.
//     fn deserialize_str<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         unimplemented!()
//     }

//     fn deserialize_string<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let s = self.input.read_string()?;
//         visitor.visit_string(s)
//     }

//     // The `Serializer` implementation on the previous page serialized byte
//     // arrays as JSON arrays of bytes. Handle that representation here.
//     fn deserialize_bytes<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let data = self.input.read_byte_array()?;
//         visitor.visit_bytes(&data)
//     }

//     fn deserialize_byte_buf<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         let data = self.input.read_byte_array()?;
//         visitor.visit_byte_buf(data)
//     }

//     fn deserialize_option<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         unimplemented!()
//     }

//     // In Serde, unit means an anonymous value containing no data.
//     fn deserialize_unit<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         unimplemented!()
//     }

//     // Unit struct means a named value containing no data.
//     fn deserialize_unit_struct<V>(
//         self,
//         _name: &'static str,
//         visitor: V,
//     ) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         self.deserialize_unit(visitor)
//     }

//     // As is done here, serializers are encouraged to treat newtype structs as
//     // insignificant wrappers around the data they contain. That means not
//     // parsing anything other than the contained value.
//     fn deserialize_newtype_struct<V>(
//         self,
//         _name: &'static str,
//         visitor: V,
//     ) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         visitor.visit_newtype_struct(self)
//     }

//     // Deserialization of compound types like sequences and maps happens by
//     // passing the visitor an "Access" object that gives it the ability to
//     // iterate through the data contained in the sequence.
//     fn deserialize_seq<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         visitor.visit_seq(
//             RQSeqAccess {
//                 deserializer: self,
//             }
//         )
//     }

//     // Tuples look just like sequences in JSON. Some formats may be able to
//     // represent tuples more efficiently.
//     //
//     // As indicated by the length parameter, the `Deserialize` implementation
//     // for a tuple in the Serde data model is required to know the length of the
//     // tuple before even looking at the input data.
//     fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         self.deserialize_seq(visitor)
//     }

//     // Tuple structs look just like sequences in JSON.
//     fn deserialize_tuple_struct<V>(
//         self,
//         _name: &'static str,
//         _len: usize,
//         visitor: V,
//     ) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         self.deserialize_seq(visitor)
//     }

//     // Much like `deserialize_seq` but calls the visitors `visit_map` method
//     // with a `MapAccess` implementation, rather than the visitor's `visit_seq`
//     // method with a `SeqAccess` implementation.
//     fn deserialize_map<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         unimplemented!()
//     }

//     // Structs look just like maps in JSON.
//     //
//     // Notice the `fields` parameter - a "struct" in the Serde data model means
//     // that the `Deserialize` implementation is required to know what the fields
//     // are before even looking at the input data. Any key-value pairing in which
//     // the fields cannot be known ahead of time is probably a map.
//     fn deserialize_struct<V>(
//         self,
//         _name: &'static str,
//         _fields: &'static [&'static str],
//         visitor: V,
//     ) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         self.deserialize_seq(visitor)
//     }

//     fn deserialize_enum<V>(
//         self,
//         _name: &'static str,
//         variants: &'static [&'static str],
//         visitor: V,
//     ) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         unimplemented!("binary enum")
//     }

//     // An identifier in Serde is the type that identifies a field of a struct or
//     // the variant of an enum. In JSON, struct fields and enum variants are
//     // represented as strings. In other formats they may be represented as
//     // numeric indices.
//     fn deserialize_identifier<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         unimplemented!("binary enum")
//     }

//     // Like `deserialize_any` but indicates to the `Deserializer` that it makes
//     // no difference which `Visitor` method is called because the data is
//     // ignored.
//     //
//     // Some deserializers are able to implement this more efficiently than
//     // `deserialize_any`, for example by rapidly skipping over matched
//     // delimiters without paying close attention to the data in between.
//     //
//     // Some formats are not able to implement this at all. Formats that can
//     // implement `deserialize_any` and `deserialize_ignored_any` are known as
//     // self-describing.
//     fn deserialize_ignored_any<V>(self, visitor: V) -> ParseResult<V::Value>
//     where
//         V: Visitor<'de>,
//     {
//         self.deserialize_any(visitor)
//     }
// }

// struct RQSeqAccess<'a, 'b> {
//     deserializer: &'a mut Deserializer<'b>,
// }

// impl<'a, 'b: 'a> SeqAccess<'b> for RQSeqAccess<'a, 'b> {
//     type Error = ParseError;

//     #[inline]
//     fn next_element_seed<V: DeserializeSeed<'b>>(&mut self, seed: V) -> ParseResult<Option<V::Value>> {
//         match DeserializeSeed::deserialize(
//             seed,
//             &mut *self.deserializer
//         ) {
//             Ok(v) => Ok(Some(v)),
//             // EOF
//             Err(ParseError::IO(e)) if e.kind() == ErrorKind::UnexpectedEof => Ok(None),
//             Err(e) => Err(e),
//         }
//     }

//     #[inline]
//     fn size_hint(&self) -> Option<usize> {
//         None
//     }
// }

// // // `MapAccess` is provided to the `Visitor` to give it the ability to iterate
// // // through entries of the map.
// // impl<'de, 'a> MapAccess<'de> for CommaSeparated<'a, 'de> {
// //     type Error = Error;

// //     fn next_key_seed<K>(&mut self, seed: K) -> ParseResult<Option<K::Value>>
// //     where
// //         K: DeserializeSeed<'de>,
// //     {
// //         // Check if there are no more entries.
// //         if self.de.peek_char()? == '}' {
// //             return Ok(None);
// //         }
// //         // Comma is required before every entry except the first.
// //         if !self.first && self.de.next_char()? != ',' {
// //             return Err(Error::ExpectedMapComma);
// //         }
// //         self.first = false;
// //         // Deserialize a map key.
// //         seed.deserialize(&mut *self.de).map(Some)
// //     }

// //     fn next_value_seed<V>(&mut self, seed: V) -> ParseResult<V::Value>
// //     where
// //         V: DeserializeSeed<'de>,
// //     {
// //         // It doesn't make a difference whether the colon is parsed at the end
// //         // of `next_key_seed` or at the beginning of `next_value_seed`. In this
// //         // case the code is a bit simpler having it here.
// //         if self.de.next_char()? != ':' {
// //             return Err(Error::ExpectedMapColon);
// //         }
// //         // Deserialize a map value.
// //         seed.deserialize(&mut *self.de)
// //     }
// // }

// // struct Enum<'a, 'de: 'a> {
// //     de: &'a mut Deserializer<'de>,
// // }

// // impl<'a, 'de> Enum<'a, 'de> {
// //     fn new(de: &'a mut Deserializer<'de>) -> Self {
// //         Enum { de }
// //     }
// // }

// // // `EnumAccess` is provided to the `Visitor` to give it the ability to determine
// // // which variant of the enum is supposed to be deserialized.
// // //
// // // Note that all enum deserialization methods in Serde refer exclusively to the
// // // "externally tagged" enum representation.
// // impl<'de, 'a> EnumAccess<'de> for Enum<'a, 'de> {
// //     type Error = ParseError;
// //     type Variant = Self;

// //     fn variant_seed<V>(self, seed: V) -> ParseResult<(V::Value, Self::Variant)>
// //     where
// //         V: DeserializeSeed<'de>,
// //     {
// //         // The `deserialize_enum` method parsed a `{` character so we are
// //         // currently inside of a map. The seed will be deserializing itself from
// //         // the key of the map.
// //         let val = seed.deserialize(&mut *self.de)?;
// //         // Parse the colon separating map key from value.
// //         if self.de.next_char()? == ':' {
// //             Ok((val, self))
// //         } else {
// //             Err(Error::ExpectedMapColon)
// //         }
// //     }
// // }

// // // `VariantAccess` is provided to the `Visitor` to give it the ability to see
// // // the content of the single variant that it decided to deserialize.
// // impl<'de, 'a> VariantAccess<'de> for Enum<'a, 'de> {
// //     type Error = ParseError;

// //     // If the `Visitor` expected this variant to be a unit variant, the input
// //     // should have been the plain string case handled in `deserialize_enum`.
// //     fn unit_variant(self) -> ParseResult<()> {
// //         Err(Error::ExpectedString)
// //     }

// //     // Newtype variants are represented in JSON as `{ NAME: VALUE }` so
// //     // deserialize the value here.
// //     fn newtype_variant_seed<T>(self, seed: T) -> ParseResult<T::Value>
// //     where
// //         T: DeserializeSeed<'de>,
// //     {
// //         seed.deserialize(self.de)
// //     }

// //     // Tuple variants are represented in JSON as `{ NAME: [DATA...] }` so
// //     // deserialize the sequence of data here.
// //     fn tuple_variant<V>(self, _len: usize, visitor: V) -> ParseResult<V::Value>
// //     where
// //         V: Visitor<'de>,
// //     {
// //         de::Deserializer::deserialize_seq(self.de, visitor)
// //     }

// //     // Struct variants are represented in JSON as `{ NAME: { K: V, ... } }` so
// //     // deserialize the inner map here.
// //     fn struct_variant<V>(
// //         self,
// //         _fields: &'static [&'static str],
// //         visitor: V,
// //     ) -> ParseResult<V::Value>
// //     where
// //         V: Visitor<'de>,
// //     {
// //         de::Deserializer::deserialize_map(self.de, visitor)
// //     }
// // }

// #[test]
// fn deser_p06() {
//     let hex = hex_literal::hex!("
//         2c 00 06 00  02 21 00 38  33 31 63 61  61 31 62 36
//         30 30 66 38  35 32 62 37  38 34 34 34  39 39 34 33
//         30 65 63 61  63 31 37 00  03 00 03 01             
//     ");

//     let mut parser = RQParser::new(&hex[4..]);
//     let all = parser.read_guess_all().unwrap();
//     let tgt = [
//         DataElementComposite::String(
//             "831caa1b600f852b7844499430ecac17".to_string(),
//         ),
//         DataElementComposite::Bool(0),
//         DataElementComposite::Bool(1),
//     ];

//     assert_eq!(tgt.as_slice(), &all);

//     let res: crate::protocol::PinResult = from_slice(&hex[4..]).unwrap();
//     let exp = crate::protocol::PinResult {
//         pin_hash: "831caa1b600f852b7844499430ecac17".to_string(),
//         bool0: false,
//         bool1: true,
//     };
    
//     assert_eq!(res, exp);
//     // println!("{all:#?}; {res:#?}")
// }

// #[test]
// fn deser_p01() {
//     let hex = hex_literal::hex!("
//         b3 00 01 00  04 d7 97 9a  01 04 75 96  9a 01 01 10
//         02 21 00 32  39 34 31 37  61 61 62 65  38 36 38 34
//         30 32 62 38  31 30 62 61  32 66 34 32  37 34 32 36
//         35 63 31 00  02 01 00 00  08 24 06 5c  da 22 58 00
//         00 02 0d 00  58 77 74 42  36 49 6c 78  36 57 62 56
//         00 02 01 00  00 03 00 03  00 04 00 00  00 00 02 06
//         00
//            36 24 4b  fe 8c 0e 19  36 02 50 ed  52 12 99 36
//         00 e0 4b 3c  1a b7 36 5e  0c 74 0e fd  14 36 00 00
//         00 00 00 00  36 00 00 00  00 00 00 04  56 af 4b c6
//         08 56 af 4b  c6 a4 fd 90  cd 02 65 6e  02 01 00 00
//         02 01 00 00  02 01 00 00  02 08 00 63  6c 61 73 73
//         69 63 00           
//     ");

//     let mut parser = RQParser::new(&hex[4..]);
//     let all = parser.read_guess_all().unwrap();
    
//     // println!("{all:#?}");
// }

// #[test]
// fn deser_p04() {
//     let hex = hex_literal::hex!("
//         0a 00 04 00  02 03 00 02  00 00
//     ");

//     let pac: crate::protocol::Packet4 = from_slice(&hex[4..]).unwrap();
//     let exp = crate::protocol::Packet4 {
//         unk0: 3,
//         unk1: 0,
//     };   
    
//     assert_eq!(pac, exp);
// }

// // #[test]
// fn deser_p46() {
//     let hex = hex_literal::hex!("
//         22 00 46 00  04 bf 26 00  00 04 3c 00  00 00 04 00
//         00 00 00 04  00 00 00 00  04 00 00 00  00 04 00 00
//         00 00 0e 00  0c 00 04 7d  a7 9a 01 04  1b a6 9a 01
//     ");

//     let mut parser = RQParser::new(&hex[4..]);
//     let all = parser.read_guess_all().unwrap();
    
//     println!("{all:#?}");
// }

// #[test]
// fn deser_p11() {
//     let hex = hex_literal::hex!("
//         b8 02 11 00  04 d5 6d 99  00 08 30 2a  00 00 00 00
//         00 00 04 00  00 00 00 04  00 02 00 00  04 00 00 00
//         00 08 24 06  5c da 22 58  00 00 02 01  00 00 04 00
//         00 00 00 02  34 00 04 25  4f 49 b7 02  01 00 03 01
//         02 01 00 04  03 00 00 00  04 1e 01 00  00 04 64 00
//         00 00 04 dd  63 00 00 1d  07 00 00 00  02 00 00 00
//         f5 52 02 00  4e 48 03 00  02 08 00 41  73 74 6f 72
//         65 61 00 01  00 08 00 00  00 00 00 00  00 00 02 06
//         00 25 03 00  00 01 04 87  00 00 00 02  01 00 04 00
//         80 00 00 04  00 00 00 00  04 00 00 00  00 04 00 00
//         00 00 02 00  00 01 00 01  00 04 00 00  00 00 01 00
//         04 00 00 00  00 25 04 00  00 01 04 44  02 00 00 02
//         01 00 04 00  80 00 00 04  00 00 00 00  04 00 00 00
//         00 04 00 00  00 00 02 00  00 01 00 01  00 04 00 00
//         00 00 01 00  04 00 00 00  00 25 05 00  00 01 04 8b
//         01 00 00 02  01 00 04 00  80 00 00 04  00 00 00 00
//         04 00 00 00  00 04 00 00  00 00 02 00  00 01 00 01
//         00 04 00 00  00 00 01 00  04 00 00 00  00 25 06 00
//         00 01 04 8a  00 00 00 02  01 00 04 00  80 00 00 04
//         00 00 00 00  04 00 00 00  00 04 00 00  00 00 02 00
//         00 01 00 01  00 04 00 00  00 00 01 00  04 00 00 00
//         00 25 08 00  00 01 04 8b  00 00 00 02  01 00 04 00
//         80 00 00 04  00 00 00 00  04 00 00 00  00 04 00 00
//         00 00 02 00  00 01 00 01  00 04 00 00  00 00 01 00
//         04 00 00 00  00 25 09 00  00 01 04 8c  00 00 00 02
//         01 00 04 00  80 00 00 04  00 00 00 00  04 00 00 00
//         00 04 00 00  00 00 02 00  00 01 00 01  00 04 00 00
//         00 00 01 00  04 00 00 00  00 04 00 00  00 00 04 00
//         00 00 00 04  00 00 00 00  04 00 00 00  00 04 00 00
//         00 00 04 00  00 00 00 04  00 00 00 00  04 00 00 00
//         00 04 00 00  00 00 04 00  00 00 00 04  00 00 00 00
//         04 00 00 00  00 04 00 00  00 00 04 00  00 00 00 04
//         00 00 00 00  04 00 00 00  00 04 00 00  00 00 04 00
//         00 00 00 04  00 00 00 00  04 00 00 00  00 04 00 00
//         00 00 04 00  00 00 00 04  00 00 00 00  04 00 00 00
//         00 04 00 00  00 00 04 00  00 00 00 04  00 00 00 00
//         04 00 00 00  00 04 00 00  00 00 04 00  00 00 00 04
//         00 00 00 00  04 00 00 00  00 04 00 00  00 00 04 00
//         00 00 00 04  00 00 00 00  04 00 00 00  00 04 00 00
//         00 00 04 00  00 00 00 04  00 00 00 00  04 00 00 00
//         00 04 00 00  00 00 04 00  00 00 00 04  00 00 00 00
//         04 00 00 00  00 04 00 00  00 00 04 00  00 00 00 04
//         00 00 00 00  04 00 00 00  00 04 00 00  00 00 04 00
//         00 00 00 04  00 00 00 00                          
//     ");

//     let mut parser = RQParser::new(&hex[4..]);
//     let all = parser.read_guess_all().unwrap();
    
//     println!("{all:#?}");
// }

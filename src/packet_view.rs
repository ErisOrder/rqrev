use std::io::Cursor;

use num_enum::TryFromPrimitive;
use pretty_hex::PrettyHex;

use crate::{
    mitm::PacketSource, protocol::{Packet, PacketType}, rqode_binrw::{BinReadChecked, read_guess_all}
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DissectionKind {
    Structured,
    Guessed,
    Binary,
    Combined,
}

#[derive(Clone, Debug)]
pub struct PacketView {
    pub id: u16,
    pub name: Option<String>,
    pub source: PacketSource,
    pub length: usize,
    pub kind: DissectionKind,
    pub text: String,
    pub pretty: bool,
    pub data: Vec<u8>,
    pub compressed: bool,
}

impl PacketView {
    pub fn redissect(&mut self, pretty: bool) {
        let compressed = self.compressed;
        *self = dissect(self.source, self.id, &self.data, pretty);
        self.compressed = compressed;
    }

    pub fn format_log(&self) -> String {
        let dir = match self.source {
            PacketSource::Client => "Client",
            PacketSource::Server => "Server",
        };
        let name = self.name.as_deref().unwrap_or("");
        let id = self.id;
        let mut text = format!("{dir}: packet {id:#X} ({id}) {name};\n");
        if self.length > 0 {
            match self.kind {
                DissectionKind::Structured | DissectionKind::Guessed => {
                    text += &format!(
                        "{:#?}\n",
                        self.data.get(2..).unwrap_or_default().hex_dump()
                    );
                    text += &self.text;
                },
                DissectionKind::Combined | DissectionKind::Binary => {
                    text += &self.text;
                },
            };
        }

        text
    }
}

pub fn packet_name(id: u16) -> Option<String> {
    PacketType::try_from_primitive(id).ok().map(|p| format!("{p:?}"))
}

fn binary(data: &[u8]) -> String {
    format!("{:#?}", data.hex_dump())
}

pub fn dissect(source: PacketSource, id: u16, data: &[u8], pretty: bool) -> PacketView {
    let name = packet_name(id);
    let body = data.get(2..).unwrap_or_default();

    // A known packet has a declared binrw structure.
    if name.is_some() {
        match Packet::read_partial(data) {
            // Auto decompress
            Ok((Packet::CompressedData(mut packet) | Packet::CompressedData2(mut packet), _)) => {
                let mut header = [0u16, 0u16];
                bytemuck::cast_slice_mut(&mut header).copy_from_slice(&packet.blob[..4]);
                let mut packet = dissect(source, header[1], &mut packet.blob[2..], pretty);
                packet.compressed = true;
                return packet;
            },
            Ok((packet, offset)) => {
                let mut text = pretty_opt_fmt(&packet, pretty);
                if offset < data.len() {
                    let rest = &data[offset..];
                    text.push_str("\nleft: ");
                    text.push_str(&binary(rest));

                    // The remaining bytes are useful to reverse engineers, but
                    // they are still not part of the successfully dissected
                    // known structure.
                    if let Ok(values) = read_guess_all(Cursor::new(rest)) {
                        text.push_str("\ntail: ");
                        text.push_str(&pretty_opt_fmt(&values, pretty));
                    }
                }
                return PacketView {
                    id,
                    name,
                    source,
                    length: body.len(),
                    kind: DissectionKind::Structured,
                    text,
                    pretty,
                    data: data.to_vec(),
                    compressed: false,
                };
            }
            // Fallback to guess
            Err(e) => {
                let parsed = match read_guess_all(Cursor::new(body)) {
                    Ok(p) => pretty_opt_fmt(&p, pretty),
                    Err(e) => error_or_stub(e, "[GUESS ERR]", pretty),
                };

                return PacketView {
                    id,
                    name,
                    source,
                    length: body.len(),
                    kind: DissectionKind::Combined,
                    text: format!("{} {:#?}\n{parsed}", error_or_stub(e, "[BINRW ERR]", pretty), body.hex_dump()),
                    pretty,
                    data: data.to_vec(),
                    compressed: false,
                };
            }
        }
    }

    match read_guess_all(Cursor::new(body)) {
        Ok(values) => PacketView {
            id,
            name,
            source,
            length: body.len(),
            kind: DissectionKind::Guessed,
            text: pretty_opt_fmt(&values, pretty),
            pretty,
            data: data.to_vec(),
            compressed: false,
        },
        Err(e) => PacketView {
            id,
            name,
            source,
            length: body.len(),
            kind: DissectionKind::Binary,
            text: format!("{} {:#?}", error_or_stub(e, "[GUESS ERR]", pretty),  body.hex_dump()),
            pretty,
            data: data.to_vec(),
            compressed: false,
        },
    }
}

fn pretty_opt_fmt(val: &impl core::fmt::Debug, pretty: bool) -> String {
    match pretty {
        true => format!("{val:#?}"),
        false => format!("{val:?}"),
    }
}

fn error_or_stub(e: impl std::error::Error, stub: &str, pretty: bool) -> String {
    match pretty {
        true => format!("{stub}\n{e:#?}"),
        false => stub.to_string(),
    }
}

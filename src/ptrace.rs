use pretty_hex::PrettyHex;

use crate::{cipher::PacketSource, rqode::RQParser};


pub fn ptrace(
    source: PacketSource,
    ptype: u16,
    data: &mut [u8],
) {
    let mut parser = RQParser::new(&data);
    let res = parser.read_guess_all();
    
    println!("{source:?}: packet {ptype:02} ({ptype:#02x}), {:#?}", data.hex_dump());
    match res {
        Ok(p) => println!("parsed: {p:?}"),
        Err(e) => println!("parse error: {e}"),
    }
}

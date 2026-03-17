use anyhow::{Result, bail};

use pretty_hex::PrettyHex;
use ringbuf::{HeapRb, traits::{Consumer, Observer, Producer}};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey, rand_core::OsRng, traits::PublicKeyParts};
use tracing::{debug, warn};

use crate::{cipher::*, protocol::PacketType, ptrace::ptrace, rqode_binrw::zlib_decompress};

const DROP: &[u16] = &[
    // 0x33, // Causes crash
    0x415,
    0x90,
    0x3E9,
    0x3EA,
    0x3FA,
    0x116,
    0x117,
    0xCE,
    0x408,
    0x410,
    0x412,
    0xEB,
    0x2780, // Triggers beginner hints
    0x1B6,

    // 0x64, // Loading stops on 97%
];

const STOP: &[u16] = &[
    // 0x415,
];

pub struct Mitm {
    cipher_state: CipherS,
    passthrough: bool,
    rx_buf: HeapRb<u8>,
    tx_buf: HeapRb<u8>,
    drop_packets: bool,
}

pub enum CipherS {
    Uninit,
    ClientHandshakeReceived {
        my_pk: RsaPrivateKey,
        game_pubk: RsaPublicKey,
    },
    EncryptedChannel {
        // Generated RX and TX
        game_rx: CustomRc4,
        game_tx: CustomRc4,

        // Server-sent RX and TX
        srv_rx: CustomRc4,
        srv_tx: CustomRc4,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketSource {
    Client,
    Server,
}

impl Mitm {
    pub fn new(
        passthrough: bool,
    ) -> Self {
        Self {
            cipher_state: CipherS::Uninit,
            passthrough,
            rx_buf: HeapRb::new(1000000),
            tx_buf: HeapRb::new(1000000),
            drop_packets: false,
        }
    }
    
    pub fn process_game_data(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.passthrough {
            println!("--> pass: {:#?}", data.hex_dump());
            return Ok(data.to_vec())
        }
        
        match &mut self.cipher_state {
            CipherS::Uninit => {
                // Expect game pubkey
                if data.len() == 132 {
                    debug!("received client pubkey");
                    
                    let game_pubk = read_game_pubkey(data)?;
                    let my_pk = rsa::RsaPrivateKey::new(&mut OsRng, 1015)?;
                    
                    // Prepare our pubkey for game
                    let mut out = vec![0; 132];
                    out[..132].fill(0);
                    let pubk = my_pk.to_public_key();
                    out[..127].copy_from_slice(&pubk.n().to_bytes_le());
                    let exp = pubk.e().to_bytes_le();
                    out[128..128+exp.len()].copy_from_slice(&exp);

                    self.cipher_state = CipherS::ClientHandshakeReceived { my_pk, game_pubk };
                    
                    Ok(out)
                } else {
                    bail!("expected client handshake: 132 bytes")
                }
            },
            CipherS::ClientHandshakeReceived { .. } => bail!("unexpected client message"),
            CipherS::EncryptedChannel { game_rx, game_tx, srv_rx, srv_tx } => {
                let mut data = data.to_vec();
                
                // Decrypt using our TX box
                game_tx.xor_in_place(&mut data);

                let mut data = Self::on_packet(
                    &mut self.drop_packets,
                    PacketSource::Client,
                    &mut self.tx_buf,
                    &data,
                );

                // println!("--> dec : {:#?}", data.hex_dump());
                // Encrypt message using server-sent TX box
                srv_tx.xor_in_place(&mut data);
                
                Ok(data)
            },
        }
    }

    pub fn process_server_data(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.passthrough {
            println!("<-- pass: {:#?}", data.hex_dump());
            return Ok(data.to_vec())
        }
        
        match &mut self.cipher_state {
            CipherS::Uninit => bail!("unexpected server message"),
            CipherS::ClientHandshakeReceived { my_pk, game_pubk } => {
                // Expect server handshake
                if data.len() == 640 {
                    debug!("received server RC4 boxes");
                    
                    let mut plaintext = vec![];
        
                    let mut data = data.to_vec();
        
                    modulus_transform(&mut data)?;
    
                    for (_i, block) in data.chunks(128).enumerate() {
                        let cipher = BigUint::from_bytes_le(block);
                        let dec = rsa::hazmat::rsa_decrypt_and_check::<OsRng>(my_pk, None, &cipher)?;
                        let dec = dec.to_bytes_le();
                        // println!("decrypted {i}: {:#?}", dec.hex_dump());
                        plaintext.extend_from_slice(&dec);
                    }

                    debug!("server RC4 boxes decoded");
                    
                    // Import boxes 
                    let srv_rx = CustomRc4::from_bytes(&plaintext[..264]);
                    let srv_tx = CustomRc4::from_bytes(&plaintext[264..528]);

                    let (game_rx, game_tx, out) = prepare_rc4_boxes();

                    self.cipher_state = CipherS::EncryptedChannel { game_rx, game_tx, srv_rx, srv_tx };

                    Ok(out)                
                } else {
                    bail!("expected server handshake: 640 bytes");
                }
            },
            CipherS::EncryptedChannel { game_rx, game_tx, srv_rx, srv_tx } => {
                let mut data = data.to_vec();
                
                // Decrypt message using server-sent RX box
                srv_rx.xor_in_place(&mut data);
                
                let mut data = Self::on_packet(
                    &mut self.drop_packets,
                    PacketSource::Server,
                    &mut self.rx_buf,
                    &data,
                );
                
                // Encrypt using our RX box
                game_rx.xor_in_place(&mut data);
                
                Ok(data)
            },
        }
    }
    
    pub fn on_packet(
        drop_all: &mut bool,
        source: PacketSource,
        buf: &mut HeapRb<u8>,
        data: &[u8],
    ) -> Vec<u8> {
        
        // println!("{source:?} INPUT: {:#?}", data.hex_dump());
        
        // Push bytes to ringbuffer
        buf.push_slice(&data);
        
        // Dequeue as much packets as possible
        let mut out = vec![];
        loop {
            if buf.occupied_len() < 4 {
                break
            }
            
            // Peek packet len & type
            let mut headr = [0u16, 0u16];
            buf.peek_slice(bytemuck::cast_slice_mut(&mut headr));

            // If buffer has not enough data
            if buf.occupied_len() < headr[0] as usize {
                break
            }

            // Stop after this packet
            if STOP.contains(&headr[1]) {
                *drop_all = true;
            }

            // Try decompress
            let mut drop_compr = false;
            if headr[1] == PacketType::CompressedData as u16 {
                let mut temp = vec![0u8; headr[0] as usize];
                buf.peek_slice(&mut temp);
               
                if let Ok(x) = zlib_decompress(&mut temp[4..]) {
                    let ptype = u16::from_le_bytes(x[2..4].try_into().unwrap());
                    drop_compr = DROP.contains(&ptype);
                }
            }
            
            // Drop this packet
            if DROP.contains(&headr[1]) || *drop_all || drop_compr {
                let mut temp = vec![0u8; headr[0] as usize];
                buf.pop_slice(&mut temp);
                
                warn!("drop this packet");
                ptrace(source, headr[1], &mut temp[2..]);
                continue;
            }

            // Pop packet data
            let clen = out.len();
            out.resize(clen + headr[0] as usize, 0);
            buf.pop_slice(&mut out[clen..]);

            // Callback
            ptrace(source, headr[1], &mut out[clen + 2..]);
        }
        
        out
    }
}


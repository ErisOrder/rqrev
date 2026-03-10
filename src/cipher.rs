#[derive(Clone)]
pub struct CustomRc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl CustomRc4 {
    pub fn new() -> Self {
        CustomRc4 {
            s: [0; 256],
            i: 0,
            j: 0,
        }
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            s: data[..256].try_into().unwrap(),
            i: u32::from_le_bytes(data[256..260].try_into().unwrap()) as u8,
            j: u32::from_le_bytes(data[260..264].try_into().unwrap()) as u8,
        }
    }

    pub fn as_bytes(&mut self) -> &mut [u8; 264] {
        unsafe { core::mem::transmute(self) }
    }

    /// Internal XOR core (used by both encrypt and decrypt)
    pub fn xor_in_place(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }

        let mut i = self.i;
        let mut j = self.j;

        for byte in data.iter_mut() {
            i = i.wrapping_add(1);

            let si = self.s[i as usize];
            j = j.wrapping_add(si);

            let sj = self.s[j as usize];

            // swap
            self.s[j as usize] = si;
            self.s[i as usize] = sj;

            // keystream byte
            let ks = self.s[(si.wrapping_add(sj)) as usize];

            *byte ^= ks;
        }

        self.i = i;
        self.j = j;
    }

    /// Dummy advance (matches sub_805390)
    pub fn dummy_advance(&mut self, steps: usize) {
        for _ in 0..steps {
            self.i = self.i.wrapping_add(1);
            let si = self.s[self.i as usize];
            let j_idx = self.j.wrapping_add(si);
            self.j = j_idx;
            self.s.swap(self.i as usize, j_idx as usize);
        }
    }
    
    pub fn setup_rand(&mut self) {
        let randarr: [u8; 256] = core::array::from_fn(|_| rand::random());
        self.setup(&randarr);
    }
    
    /// Full setup (KSA + 1000 dummy steps) – call once per session/key
    pub fn setup(&mut self, extra_256: &[u8; 256]) {
        // Vectorized identity init (scalar equivalent)
        for i in 0..256u32 {
            self.s[i as usize] = i as u8;
        }

        self.j = 0;
        for i in 0..256usize {
            let si = self.s[i];
            let extra = extra_256[i];
            let j_idx = (self.j.wrapping_add(si).wrapping_add(extra)) & 0xFF;
            self.j = j_idx;
            self.s.swap(i, j_idx as usize);
        }

        // 1000 dummy PRGA steps (exact match to sub_805AC0)
        self.i = 0;
        self.j = 0;
        for _ in 0..1000 {
            self.i = self.i.wrapping_add(1);
            let si = self.s[self.i as usize];
            let j_idx = self.j.wrapping_add(si);
            self.j = j_idx;
            self.s.swap(self.i as usize, j_idx as usize);
        }
    }
}


//     /// In-place encryption (matches sub_8051D0)
//     pub fn encrypt_in_place(&mut self, data: &mut [u8]) {
//         self.xor_in_place(data);
//     }

//     /// In-place decryption (identical to encryption)
//     pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
//         self.xor_in_place(data);   // same call!
//     }


use anyhow::{Result, bail};
use pretty_hex::PrettyHex;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey, rand_core::OsRng, traits::PublicKeyParts};

pub enum CipherS {
    Passthrough,
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

impl CipherS {
    pub fn process_game_message(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            CipherS::Passthrough => {
                println!("--> pass: {:#?}", data.hex_dump());
                Ok(data.to_vec())
            },
            CipherS::Uninit => {
                println!("--> hand: {:#?}", data.hex_dump());
                
                // Expect game pubkey
                if data.len() == 132 {
                    let n = BigUint::from_bytes_le(&data[..128]);
                    let e = BigUint::from_bytes_le(&data[128..132]);
        
                    let game_pubk = rsa::RsaPublicKey::new(n, e)?;
                    let my_pk = rsa::RsaPrivateKey::new(&mut OsRng, 1015)?;
                    
                    // Prepare our pubkey for game
                    let mut out = vec![0; 132];
                    out[..132].fill(0);
                    let pubk = my_pk.to_public_key();
                    out[..127].copy_from_slice(&pubk.n().to_bytes_le());
                    let exp = pubk.e().to_bytes_le();
                    out[128..128+exp.len()].copy_from_slice(&exp);

                    *self = Self::ClientHandshakeReceived { my_pk, game_pubk };
                    
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
                println!("--> dec : {:#?}", data.hex_dump());
                // Encrypt message using server-sent TX box
                srv_tx.xor_in_place(&mut data);
                
                Ok(data)
            },
        }
    }

    pub fn process_server_message(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            CipherS::Passthrough => {
                println!("--> pass: {:#?}", data.hex_dump());
                Ok(data.to_vec())
            },
            CipherS::Uninit => bail!("unexpected server message"),
            CipherS::ClientHandshakeReceived { my_pk, game_pubk } => {
                println!("<-- hand_raw: {:#?}", data.hex_dump());
                
                // Expect server handshake
                if data.len() == 640 {
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

                    println!("<-- hand_decoded: {:#?}", plaintext.hex_dump());
                    
                    // Import boxes 
                    let srv_rx = CustomRc4::from_bytes(&plaintext[..264]);
                    let srv_tx = CustomRc4::from_bytes(&plaintext[264..528]);

                    // Create boxes for client
                    let mut game_rx = CustomRc4::new();
                    let mut game_tx = CustomRc4::new();
                    // game_rx.setup_rand();
                    // game_tx.setup_rand();
                    let mut unprep_game_rx = game_rx.clone();
                    // Apply transform to our box; same transform will be applied by client
                    modulus_transform(game_rx.as_bytes())?;

                    // Prepare message for client
                    let mut out = vec![0; 640];
                    out[..264].copy_from_slice(unprep_game_rx.as_bytes());
                    out[264..528].copy_from_slice(game_tx.as_bytes());
                    // TODO: Is this just junk?
                    out[528..640].fill(0);

                    *self = CipherS::EncryptedChannel { game_rx, game_tx, srv_rx, srv_tx };

                    Ok(out)                
                } else {
                    bail!("expected server handshake: 640 bytes");
                }
            },
            CipherS::EncryptedChannel { game_rx, game_tx, srv_rx, srv_tx } => {
                let mut data = data.to_vec();
                
                // Decrypt message using server-sent RX box
                srv_rx.xor_in_place(&mut data);
                println!("<-- dec : {:#?}", data.hex_dump());
                // Encrypt using our RX box
                game_rx.xor_in_place(&mut data);
                
                Ok(data)
            },
        }
    }
}

pub fn modulus_transform(data: &mut [u8]) -> Result<()> {
    // Strange stage: encrypt first 128 bytes with fixes pubkey with broken construction
    let pseudo_n = BigUint::from_bytes_le(&MODULUS_PSEUDO);
    let e = BigUint::from(0x10001u32);
    let pseudok = RsaPublicKey::new(pseudo_n, e)?;
    let plain = BigUint::from_bytes_le(&data[..128]);
    let enc = rsa::hazmat::rsa_encrypt(&pseudok, &plain)?.to_bytes_le();
    data[..128].fill(0);
    // data[..127].copy_from_slice(&enc.to_bytes_le()[..127]);
    data[..enc.len()].copy_from_slice(&enc);
    Ok(())
}

// Probably modulus of a server, stored in a very tricky way
const MODULUS_PSEUDO: [u8; 128] = hex_literal::hex!("
    3D52C3B3C7413603B84172A8E59770B7
    FA0F85384AF5C155972D1ADE1AC2D52A
    400390A846752A973F7A88C6E374C757
    19E07E93E02F52D17EEEE0287A7384CA
    838754D5949CBB68A3A2E61BC01D0613
    6B13F0586CCF91AEEA5D3093BC600B28
    03BF8D1F0C6DA7738AB4D561BAA145BA
    95805AFD23F606E5520C104091A36E42
");

const PRIME1: [u8; 256] = hex_literal::hex!("
    37ED2BED6AD920463C45B0DCC352F308
    BFBAE183731D258CFE5AC5464401E7B8
    2CA89385D3186EAD483DE051C863DFD9
    EB8170789547FD1AFBCA68B17E5A83B9
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    
");

const PRIME2: [u8; 256] = hex_literal::hex!("
    F7CE549B65C5DF22C04982D1B89696FC
    C892A6E734B04D3BA4932454F2309592
    F77A1285C85338F8AFD3BAC9C48AB0A1
    151DC7EC92C56ADE06295C536ED14C00
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
    00000000000000000000000000000000
");

const PRIV_EXPO: [u8; 128] = hex_literal::hex!("
    359F5A9980CCF6AC3B47E070D258301F
    F45F705341C2CCADA8C2C34BED2D7907
    731EEA353F46F528F58E1063DB8A1C8D
    C068452851E194677365280A77F4ED36
    2265A361B9E15BA9DF030F3843C2ABF6
    7353C853EEF3812899929F4B1C766C74
    CCA62388BDF48E28848CC304586EB8B4
    38D418FAFFB647BA73BFB5843EE80D00
");

const PUBKEY_MODULUS: [u8; 128] = hex_literal::hex!("
    11225051C1251E7EB84A744AE2544037
    BD8EFAF3F7C884B1D28655F4E891429A
    AA5B2C27E1C4D1F4AFCDFB66E831A463
    1CC8548DD558AE2E372EF2BBD9BB802D
    E685CAB6AA091F62D86629D46D22E152
    DF236EB77783384650D976599A2AD4A5
    BF129D8D80836ADD7A17822DA9132BE0
    30270BD103A916A8A95B570DC3AA3700
");

// Encrypted and obfuscated handshake
const HANDSHAKE_MSG: [u8; 640] = hex_literal::hex!("
    a6 29 d3 07  9c 2d 90 69  55 63 5a 61  25 6f b9 29
    d8 62 1a 6b  bb 10 84 1e  b0 8a 68 c1  5e 7b 79 b5
    44 ee 70 f4  f3 f1 6f a4  6b f5 f7 62  b1 61 52 b8
    5a 46 da 1a  46 91 a3 36  b5 53 bd 51  b8 2c 48 a7
    04 ec c8 99  c3 14 e1 ea  dd b4 91 cd  80 82 67 8d
    06 85 41 73  89 92 57 39  b9 f6 9b 0e  3b 63 cf 0a
    87 22 5f bf  78 41 de 11  4c 0d 12 f3  5b 21 0d 83
    8f c1 5c 4e  69 09 9b 3e  92 83 c6 c3  4e 97 6e 32
    e6 f5 dc 15  c7 57 ec b6  4b 1b 46 a7  83 fc be f4
    c9 23 4d c0  ae 19 e9 96  f1 18 f5 8a  b4 63 f2 06
    c0 88 33 b2  34 83 95 07  0e 61 be 84  62 38 df 8d
    a9 e6 91 5f  a9 3a 8f 7e  08 00 71 cf  7d ed 73 ff
    26 04 ce cf  71 d0 e7 ed  54 97 3d 75  2b 8a 37 9c
    02 4a 21 32  42 7b b9 33  86 8a bd 01  a5 0f c7 cb
    8c b1 83 c5  35 a2 d2 c7  86 05 87 ea  dc c9 ac b2
    3d d5 d6 5c  b3 c7 4c 42  e4 40 20 d6  45 4e 01 00
    71 da 85 9c  8e 1b e2 d6  a9 dc ad c8  c7 3e 57 2e
    37 d2 12 00  38 ad 82 17  65 fe 72 87  6a e3 d8 d8
    0c f7 d7 91  a9 5b fe 32  04 1c a8 84  0d 82 e1 8d
    0f 64 eb ba  63 8e fd aa  42 d8 a3 60  a4 c8 f1 cd
    87 b0 f4 7c  a6 a2 4a 46  3d b4 e6 db  0f 65 dd 72
    07 3a 97 f7  a6 4b 02 9e  d7 e6 6b df  e1 3c 4a 50
    a3 60 fb 14  bd cf ca b5  69 08 49 3d  88 e5 b0 a5
    4c c4 cb c0  05 a8 17 08  35 48 30 95  a7 f3 0f 00
    65 42 07 f3  56 7d 85 3d  1e 6b dd 6c  48 d8 b0 35
    8c a5 42 a2  cd f8 4b d5  d6 51 aa 45  e9 14 c4 8f
    e4 b8 42 e0  1e f8 25 d5  22 ca 79 9d  b8 e0 cd df
    d3 0c d0 33  8b 4a 67 f8  70 85 93 b4  74 45 c7 14
    53 e2 41 6b  f6 9c 63 37  fc 70 21 99  48 a8 ea e3
    a7 47 e5 b7  4f d7 30 cd  d0 4a 80 ff  75 77 51 b3
    b0 3a 54 a4  66 3c 62 91  c6 91 f4 8e  9f 90 08 f6
    59 5f c2 cc  e2 57 d9 12  4f df c9 dc  9f b5 34 00
    a1 4a 53 a7  d1 66 5c 4b  47 71 fe d3  89 86 6c af
    34 5b af 68  9e 58 a4 34  9e 03 cb 39  58 c7 64 6e
    14 cc 40 9f  7c 0c a6 e6  cf 95 e5 c6  d1 4f a7 2b
    95 fc e3 43  19 0c a7 69  89 0a 60 74  12 54 c7 07
    22 aa c9 f1  a7 39 7a bf  3d cb 32 d9  08 9f 10 27
    31 c4 93 86  ca 3e 4e a5  b5 b8 e5 d8  30 9e 95 01
    e8 05 a8 15  1e 12 f7 d6  e0 b5 c1 3d  9e b9 f3 73
    ff 1e 6d 21  cb 1d 1f eb  83 76 2e a0  f6 12 21 00
");

// Deobfuscated handshake
const AFTER_MOD: [u8; 640] = hex_literal::hex!("
    75 3B 74 00 F5 54 3D A1 40 7D 4E B0 1E C8 C9 60
    C2 7C 1D 1C 33 A2 24 43 EA 9B 0A 78 3F 2E 01 B8
    F6 E8 8C 85 DC 15 B8 B2 70 56 70 91 BA DB 36 3B
    65 32 44 67 17 F1 84 34 73 14 AE 89 14 18 1F D5
    9B A8 C1 FF 6B 14 21 60 22 54 FD 9C 40 7A 5A 14
    1F D0 C1 24 7B 22 C2 41 3F A6 2D D0 CA 3E 41 18
    69 C8 40 D6 E7 04 A5 4A 9F 5B 8F E4 D8 17 07 16
    6A A0 CF F9 BB 3D 29 10 70 56 BD 47 D2 97 07 00
    E6 F5 DC 15 C7 57 EC B6 4B 1B 46 A7 83 FC BE F4
    C9 23 4D C0 AE 19 E9 96 F1 18 F5 8A B4 63 F2 06
    C0 88 33 B2 34 83 95 07 0E 61 BE 84 62 38 DF 8D
    A9 E6 91 5F A9 3A 8F 7E 08 00 71 CF 7D ED 73 FF
    26 04 CE CF 71 D0 E7 ED 54 97 3D 75 2B 8A 37 9C
    02 4A 21 32 42 7B B9 33 86 8A BD 01 A5 0F C7 CB
    8C B1 83 C5 35 A2 D2 C7 86 05 87 EA DC C9 AC B2
    3D D5 D6 5C B3 C7 4C 42 E4 40 20 D6 45 4E 01 00
    71 DA 85 9C 8E 1B E2 D6 A9 DC AD C8 C7 3E 57 2E
    37 D2 12 00 38 AD 82 17 65 FE 72 87 6A E3 D8 D8
    0C F7 D7 91 A9 5B FE 32 04 1C A8 84 0D 82 E1 8D
    0F 64 EB BA 63 8E FD AA 42 D8 A3 60 A4 C8 F1 CD
    87 B0 F4 7C A6 A2 4A 46 3D B4 E6 DB 0F 65 DD 72
    07 3A 97 F7 A6 4B 02 9E D7 E6 6B DF E1 3C 4A 50
    A3 60 FB 14 BD CF CA B5 69 08 49 3D 88 E5 B0 A5
    4C C4 CB C0 05 A8 17 08 35 48 30 95 A7 F3 0F 00
    65 42 07 F3 56 7D 85 3D 1E 6B DD 6C 48 D8 B0 35
    8C A5 42 A2 CD F8 4B D5 D6 51 AA 45 E9 14 C4 8F
    E4 B8 42 E0 1E F8 25 D5 22 CA 79 9D B8 E0 CD DF
    D3 0C D0 33 8B 4A 67 F8 70 85 93 B4 74 45 C7 14
    53 E2 41 6B F6 9C 63 37 FC 70 21 99 48 A8 EA E3
    A7 47 E5 B7 4F D7 30 CD D0 4A 80 FF 75 77 51 B3
    B0 3A 54 A4 66 3C 62 91 C6 91 F4 8E 9F 90 08 F6
    59 5F C2 CC E2 57 D9 12 4F DF C9 DC 9F B5 34 00
    A1 4A 53 A7 D1 66 5C 4B 47 71 FE D3 89 86 6C AF
    34 5B AF 68 9E 58 A4 34 9E 03 CB 39 58 C7 64 6E
    14 CC 40 9F 7C 0C A6 E6 CF 95 E5 C6 D1 4F A7 2B
    95 FC E3 43 19 0C A7 69 89 0A 60 74 12 54 C7 07
    22 AA C9 F1 A7 39 7A BF 3D CB 32 D9 08 9F 10 27
    31 C4 93 86 CA 3E 4E A5 B5 B8 E5 D8 30 9E 95 01
    E8 05 A8 15 1E 12 F7 D6 E0 B5 C1 3D 9E B9 F3 73
    FF 1E 6D 21 CB 1D 1F EB 83 76 2E A0 F6 12 21 00
");

// Known plaintext for key pair
const AFTER_DECRYPT: [u8; 640] = hex_literal::hex!("
    63 B9 E2 C2 B1 23 B7 0B 8F CD 87 A3 74 73 F1 EA
    59 4D 7C 46 E8 BC 3D A4 88 B5 A2 E4 F0 60 53 84
    8A 2C F7 CA 77 30 83 64 20 40 8D 75 78 7B 0A AF
    43 18 2D 67 EB A0 5A F2 06 AB 4F D5 3C 8B 1E 6D
    4B 1F FC 35 70 BF 6F 81 9A A8 29 97 A6 B3 04 AE
    C3 F6 7F B8 4C 0D F9 ED 9D 36 3A 61 41 D3 DB 98
    62 11 76 45 55 47 9F DF 1C 79 FD C6 E5 D6 08 80
    48 54 42 E6 66 E9 5C DA DD 9E 33 A1 D8 16
                                              44 F4
    D2 37 99 00 58 EF 39 C5 2E C8 13 0F 0E 09 A7 B2
    15 A9 BA CF C4 91 3E 5D 22 0C 17 DE 9B 1A 32 68
    1B 49 72 8C 6C 85 D0 51 05 B6 86 96 2B F8 BD 50
    C1 07 6B D1 7A BB 7E FB 1D AD 4E 01 4A FE 3F D4
    FF 38 5B 5F 21 57 C0 F3 14 34 EE 3B 2F CE E0 56
    71 27 26 C9 C7 B0 93 52 E1 CC 94 89 92 65 6E B4
    95 DC 8E 19 9C 5E AC A5 E3 7D EC 69 6A D9 31 10
    03 02 90 FA F5 2A E7 28 BE 24 25 D7
                                        CB AA 12 82
    E8 00 00 00 56 00 00 00 CD 75 38 18 42 81 99 04
    E1 09 3A 17 F1 50 87 A1 71 EC 65 FA B6 0C 0A C5
    F7 3F F0 11 8E 95 D2 A4 8D FD 0D 4C 4D 78 56 9D
    6B E0 83 B5 AC D1 4B 3E 08 ED 62 16 9C 60 2B 8C
    2A 27 B9 43 2E 68 CA 90 BF 98 8A C1 57 DD 8F 0F
    B7 CB 1A A0 52 93 01 37 23 47 5F E4 54 AB 4F C0
    D0 1F 1B E6 19 3C A2 96 32 31 E8 F6 1C EF FE AD
    30 E5 2D A9 00 1D B4 69 97 BB
                                  D3 44 07 49 2C DF
    9B 40 BA F3 86 10 AE 05 F2 4E 29 9F 22 7E DB 13
    C8 88 5C A8 5D 66 B2 02 7B 53 BC C4 D9 91 D8 63
    9A 67 77 35 6D 46 C7 20 F5 06 5B 74 D5 0B 82 5A
    51 9E 6A F8 B3 C2 DC FB B1 CC 89 DE 24 6F 85 70
    7D 26 21 DA 7C 55 E9 AF A7 C6 D7 C9 15 E3 D6 59
    FF EB F4 12 80 94 A3 72 4A 1E 7A 34 25 48 41 14
    8B E7 B8 2F A6 A5 EA FC 61 BD 3B 92 36 73 33 03
    CF AA 6E 28 6C 64 76 3D
                            58 E2 CE B0 5E BE 39 D4
    84 7F 45 0E F9 EE C3 79 E8 00 00 00 83 00 00 00
    
    34 5B AF 68 9E 58 A4 34 9E 03 CB 39 58 C7 64 6E
    14 CC 40 9F 7C 0C A6 E6 CF 95 E5 C6 D1 4F A7 2B
    95 FC E3 43 19 0C A7 69 89 0A 60 74 12 54 C7 07
    22 AA C9 F1 A7 39 7A BF 3D CB 32 D9 08 9F 10 27
    31 C4 93 86 CA 3E 4E A5 B5 B8 E5 D8 30 9E 95 01
    E8 05 A8 15 1E 12 F7 D6 E0 B5 C1 3D 9E B9 F3 73
    FF 1E 6D 21 CB 1D 1F EB 83 76 2E A0 F6 12 21 00
");

#[test]
pub fn test_cipher() {
    let n = BigUint::from_bytes_le(&PUBKEY_MODULUS);
    let e = BigUint::from(65537u32);
    let d = BigUint::from_bytes_le(&PRIV_EXPO);
    let primes = vec![
        BigUint::from_bytes_le(&PRIME1),
        BigUint::from_bytes_le(&PRIME2),
    ];
    
    let game_pk = RsaPrivateKey::from_components(n, e, d, primes).unwrap();
    let _game_pubk = game_pk.to_public_key();

    let mut msg = HANDSHAKE_MSG.to_vec();

    // Strange stage: encrypt first 128 bytes with fixed pubkey with broken construction
    // How to reverse this? how to prepare plaintext?
    // -- well, we don't need to:
    // first block contains RC4 box [256] and 2... variables
    // to forge keys, we just need to encrypt random data with the same key and remember result
    let pseudo_n = BigUint::from_bytes_le(&MODULUS_PSEUDO);
    let e = BigUint::from(0x10001u32);
    let pseudok = RsaPublicKey::new(pseudo_n, e).unwrap();
    let plain = BigUint::from_bytes_le(&msg[..128]);
    let enc = rsa::hazmat::rsa_encrypt(&pseudok, &plain).unwrap();
    msg[..128].fill(0);
    msg[..127].copy_from_slice(&enc.to_bytes_le()[..127]);
    
    assert_eq!(msg, AFTER_MOD);
    
    let mut out = vec![];
    for (i, block) in msg.chunks(128).enumerate() {
        let cipher = BigUint::from_bytes_le(block);
        let dec = rsa::hazmat::rsa_decrypt_and_check::<OsRng>(&game_pk, None, &cipher).unwrap();
        let dec = dec.to_bytes_le();
        println!("decrypted {i}: {:#?}", dec.hex_dump());
        out.extend_from_slice(&dec);
    }

    assert_eq!(AFTER_DECRYPT[..528], out[..528]);
}

#[test]
pub fn rc4_roundtrip() {
    let data: [u8; 243] = core::array::from_fn(|i| i as u8);
    let mut data_rd = data.clone();

    let mut rc4 = CustomRc4::new();
    rc4.setup_rand();
    let mut enc = rc4.clone();
    let mut dec = rc4;

    enc.xor_in_place(&mut data_rd);
    dec.xor_in_place(&mut data_rd);

    assert_eq!(data, data_rd);
}

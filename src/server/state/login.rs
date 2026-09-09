
use crate::server::prelude::*;
use crate::server::connection::ConnectionInfo;

impl State {
    pub async fn handle_auth_request(
        &self,
        info: &mut ConnectionInfo,
        p: AuthRequest
    ) -> Result<ServerList> {
        // Fill in account info
        let session = rand::random();
        info.session = Some(session);

        self.sessions.write().insert(session, p.account_id.into_string());

        let p = ServerList {
            servers: RVec::from(vec![
                ServerDesc {
                    id: U16(4),
                    name: "Eris Order".into(),
                    unk1: U32(2)
                }
            ]),
            // For now replicate exactly
            // I haven't figured out it yet
            // If you fail, game will either crash or stuck in server select
            unk1: RVec { data: vec![U16(4), U16(6), U16(5), U16(0), U16(6), U16(0), U16(7), U16(0), U16(8), U16(0)] }, 
            unk2: RVec { data: vec![U16(0), U16(10), U16(0), U16(11), U16(0), U16(12), U16(9), U16(51), U16(0)] }, 
            endpoints: RVec::from(vec![
                EndpointDesc {
                    server_id: U16(4),
                    ip: "224.53.9.37".parse().unwrap(),
                    port: U16(4254),
                    unk3: U16(18),
                }
            ]),
            unk4: U32(0),
            unk5: RBool(0),
            unk6: U32(0),
            unixtime: U64(chrono::Utc::now().timestamp() as u64),
            unk8: U32(579773625),
            mb_selected_server_id: U16(4),
            unk10: U64(10800),
            unk11: [2].into(),
            unk12: U32(328192),
            xkey0: U32(10055125),
            xkey1: U64(session),
            rdtsc_echo: p.rdtsc,
            unk16: RString::empty(),
        };
        
        Ok(p)
    }

    pub async fn handle_charlist_req(
        &self,
        info: &mut ConnectionInfo,
        req: TimeSyncResponse
    ) -> Result<CharList> {
        let session = req.xkey1.0;       

        info.session = Some(session);
        
        let Some(account) = self.sessions.read().get(&session).cloned() else {
            bail!("no session {session}")
        };
        
        let Some(ids) = self.db.get_characters(&account).await? else {
            bail!("no user {account:?}")
        };
        
        let mut chars = vec![CharacterSlot { id: U32(0), info: None }; 52];
        for (slot, id) in chars.iter_mut().zip(ids) {
            // Load to mem
            self.load_char_from_db(id).await?;

            let char = &self.chardata.read()[&id];
            
            slot.id = U32(id);
            slot.info = Some(CharacterInfo {
                class: U16(char.char.class),
                sex: RBool(char.char.sex as u8),
                level: U16(char.char.level),

                unk3: U32(0),
                hp: U32(0),
                mp: U32(0),
                location_id: U32(char.char.location),
                body: char.char.body,
                name: char.char.name.clone().into(),
                unk9: U8(0),
                unk10: U64(0),
                equip: RVec::from(vec![]),
            });
        }
        
        let p = CharList {
            xkey0: req.xkey0,
            unk1: U64(10800),
            unk2: U32(0),
            some_flags: U32(512),
            unk4: U32(0),
            rdtsc_echo: req.rdtsc,
            unk5: RString::empty(),
            unk6: U32(0),
            chars: RVec::from(chars),
        };

        Ok(p)
    }

    pub async fn handle_enter_world_req(
        &self,
        info: &mut ConnectionInfo,
        p: EnterWorldRequest,
    ) -> Result<EnterWorldResponse> {
        let Some(session) = info.session else {
            bail!("no session")
        };
        
        let Some(account) = self.sessions.read().get(&session).cloned() else {
            bail!("no session {session}")
        };
        
        let Some(ids) = self.db.get_characters(&account).await? else {
            bail!("no user {account:?}")
        };
        
        match ids.get(p.char_idx.0 as usize).copied() {
            Some(id) if id != 0 => {
                let id = id;

                // Create character message channel
                info.character_id = Some(id);
                let (tx, rx) = flume::unbounded();
                self.player_tx.write().insert(id, tx);
                self.player_rx.write().insert(id, rx);
                
                // Char certainly loaded at this point
                let shard = self.chardata.read()[&id].char.location;

                info.shard_id = Some(shard);
                
                // Send message to starting shard
                self.send_msg_to_shard(info, shard, MessageForShard::PlayerEnter { id })?;
                
                Ok(EnterWorldResponse { unk: U16(0) })
            },
            _ => {
                // FIXME: Actual code?
                Ok(EnterWorldResponse { unk: U16(1) })
            },
        }
    }
}

pub fn chars() -> Vec<CharacterSlot> {
    // Empty slots required for new characters
    vec![
        CharacterSlot { id: U32(34), info: Some(CharacterInfo {
            class: U16(4),
            sex: RBool(0),
            level: U16(999),
            unk3: U32(0),
            hp: U32(100),
            mp: U32(100),
            location_id: U32(25565),
            body: BodyParam {
                haircolor: 0,
                unk1: 0,
                skin: 0,
                unk3: 0,
                unk4: 0,
                face: 0,
                unk6: 0,
                unk7: 0
            },
            name: "Аве Эрис".into(),
            unk9: U8(0),
            unk10: U64(0),
            equip: RVec::from(starter_pack())
        }) },
        CharacterSlot { id: U32(0), info: None },
        CharacterSlot { id: U32(0), info: None },
        CharacterSlot { id: U32(0), info: None },
    ]    
}

pub fn starter_pack() -> Vec<ItemDesc> {
    vec![
        ItemDesc {
            // Chest armor
            slot: InvSlot { idx: 3, unk1: 0, tab: 0, inv: 1 },
            id: U32(5143),
            count: U16(1),
            flags: U32(0x0000),
            unk5: None,
            unk6: None,
            ext: None
        },
        ItemDesc {
            // Right hand weapon 
            slot: InvSlot { idx: 4, unk1: 0, tab: 0, inv: 1 },
            id: U32(309),
            count: U16(1),
            flags: U32(0x0000),
            unk5: None,
            unk6: None,
            ext: None
        },
        ItemDesc {
            // Left hand weapon 
            slot: InvSlot { idx: 5, unk1: 0, tab: 0, inv: 1 },
            id: U32(2244),
            count: U16(1),
            flags: U32(0x0000),
            unk5: None,
            unk6: None,
            ext: None
        },
    ]
}

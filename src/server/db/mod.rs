
pub mod model;

use async_trait::async_trait;
use model::*;
use anyhow::Result;

#[async_trait]
pub trait Database {
    async fn read_character(&self, id: u32) -> Result<Option<CharacterBundle>>;
    async fn get_characters(&self, account_id: &str) -> Result<Option<Vec<u32>>>;
}

pub struct MockDatabase;

#[async_trait]
impl Database for MockDatabase {
    async fn read_character(&self, id: u32) -> Result<Option<CharacterBundle>> {
        let stats = Stats {
            current_hp: 100,
            max_hp: 100,
            current_energy: 100,
            max_energy: 100
        };
        
        let bundle = match id {
            34 => CharacterBundle {
                char: Character {
                    id,
                    sex: false,
                    body: Default::default(),
                    class: 1,
                    name: "Lambda".to_string(),
                    level: 34,
                    pos: glam::Vec2 { x: 0.0, y: 0.0 },
                    location: 25565
                },
                stats
            },
            6 => CharacterBundle {
                char: Character {
                    id,
                    sex: false,
                    body: Default::default(),
                    class: 1,
                    name: "Nik".to_string(),
                    level: 39,
                    pos: glam::Vec2 { x: 0.0, y: 0.0 },
                    location: 25565
                },
                stats
            },
            19 => CharacterBundle {
                char: Character {
                    id,
                    sex: false,
                    body: Default::default(),
                    class: 1,
                    name: "Sam".to_string(),
                    level: 19,
                    pos: glam::Vec2 { x: 0.0, y: 0.0 },
                    location: 25565
                },
                stats
            },
            _ => return Ok(None),
        };
        
        Ok(Some(bundle))
    }
    
    async fn get_characters(&self, account_id: &str) -> Result<Option<Vec<u32>>> {
        let v = match account_id {
            "nik" => vec![6],
            "lev" => vec![34],
            "sam" => vec![19],
            _ => return Ok(None)
        };

        Ok(Some(v))
    }
}

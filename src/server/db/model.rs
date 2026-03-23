use glam::Vec2;

use crate::rqode_binrw::BodyParam;

#[derive(Clone, Debug)]
pub struct Character {
    pub id: u32,
    pub sex: bool,
    pub body: BodyParam,
    pub class: u16,
    
    pub name: String,
    pub level: u16,
    
    pub pos: Vec2,
    pub location: u32,
}

#[derive(Clone, Debug)]
pub struct Stats {
    pub current_hp: u32,
    pub max_hp: u32,
    pub current_energy: u32,
    pub max_energy: u32,
}

#[derive(Clone, Debug)]
pub struct CharacterBundle {
    pub char: Character,
    pub stats: Stats,
}




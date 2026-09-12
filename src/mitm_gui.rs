use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    sync::Arc,
    thread,
};

use parking_lot::Mutex;
use flume::{Receiver, Sender};
use eframe::egui;
use egui::{Color32, OutputCommand};
use winit::platform::windows::EventLoopBuilderExtWindows;
use serde::{Deserialize, Serialize};

use crate::{
    mitm::PacketSource,
    packet_view::PacketView,
    protocol::PacketType,
};

const CLEAR_THRESHOLD: usize = 4000;
const CLEAR_COUNT: usize = 1000;
const EVENT_CAPACITY: usize = 8192;

#[derive(Clone, Debug)]
pub struct PacketEvent {
    pub packet: PacketView,
    pub dropped: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub collapse: Vec<u16>,
    pub highlight: Vec<u16>,
    pub drop: Vec<(Vec<u16>, bool)>,
    pub mask: Vec<(Vec<u16>, bool)>,
    pub hide: Vec<(Vec<u16>, bool)>,
    pub paused: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            collapse: vec![
                PacketType::GuildAvatar as u16,
                PacketType::ServerVars as u16,
            ],
            highlight: Vec::new(),
            drop: Vec::new(),
            mask: Vec::new(),
            hide: vec![
                (vec![
                    PacketType::HeartbeatClient as u16,
                    PacketType::HeartbeatServer as u16,
                    PacketType::Heartbeat2 as u16,
                    PacketType::Heartbeat3 as u16,
                    PacketType::StatUpdate as u16,
                ], true),
                (vec![
                    PacketType::EntityMove as u16,
                    PacketType::CharacterMove as u16,
                ], true)
            ],
            paused: false,
        }
    }
}

impl Settings {
    pub fn path() -> PathBuf {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
        exe.parent().unwrap_or_else(|| std::path::Path::new("."))
            .join("mitm-gui.toml")
    }

    pub fn load() -> Self {
        let path = Self::path();
        fs::read_to_string(path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let path = Self::path();
        if let Ok(s) = toml::to_string_pretty(self) {
            let tmp = path.with_extension("toml.tmp");
            if fs::write(&tmp, s).is_ok() {
                let _ = fs::rename(tmp, path);
            }
        }
    }

    pub fn contains(list: &[u16], id: u16) -> bool {
        list.binary_search(&id).is_ok()
    }

    pub fn normalize(list: &mut Vec<u16>) {
        list.sort_unstable();
        list.dedup();
    }

    pub fn normalize_all(&mut self) {
        for (hide, _) in &mut self.hide {
            Self::normalize(hide);
        }
        Self::normalize(&mut self.collapse);
        Self::normalize(&mut self.highlight);
        for (drop, _) in &mut self.drop {
            Self::normalize(drop);
        }
        for (mask, _) in &mut self.mask {
            Self::normalize(mask);
        }
    }

    pub fn should_drop(&self, id: u16) -> bool {
        self.drop.iter()
            .filter(|d| d.1)
            .any(|d| d.0.contains(&id))
    }

    pub fn should_show(&self, id: u16) -> bool {
        let any_mask = self.mask.iter().any(|m| m.1);
        let mask_pass = self.mask.iter()
            .filter(|m| m.1)
            .any(|m| m.0.contains(&id));

        let hide = self.hide.iter()
                .filter(|h| h.1)
                .any(|h| h.0.contains(&id));
        
        (!any_mask || mask_pass) && !hide
    }
}

pub fn start() -> MitmGuiState {
    let (tx, rx) = flume::bounded(EVENT_CAPACITY);
    let state = MitmGuiState {
        tx,
        rx,
        settings: Arc::new(Mutex::new(Settings::load()))
    };

    let appstate = state.clone();
    thread::Builder::new()
        .name("rqrev-mitm-gui".into())
        .spawn(move || {
            let options = eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_title("MITM packet tracer")
                    .with_inner_size([1400.0, 1200.0]),
                event_loop_builder: Some(Box::new(|evb| { evb.with_any_thread(true); })),
                ..Default::default()
            };

            let _ = eframe::run_native(
                "MITM packet tracer",
                options,
                Box::new(|cc| Ok(Box::new(App::new(cc, appstate)))),
            );
        })
        .expect("failed to start MITM GUI");

    state
}

#[derive(Clone)]
pub struct MitmGuiState {
    pub tx: Sender<PacketEvent>,
    pub rx: Receiver<PacketEvent>,
    pub settings: Arc<Mutex<Settings>>,
}

struct App {
    state: MitmGuiState,
    packets: VecDeque<PacketEvent>,
    input: [String; 3],
    hide_input: Vec<String>,
    mask_input: Vec<String>,
    drop_input: Vec<String>,
}

impl App {
    fn new(
        _cc: &eframe::CreationContext<'_>,
        state: MitmGuiState,
    ) -> Self {
        Self {
            state,
            packets: VecDeque::with_capacity(CLEAR_THRESHOLD),
            input: Default::default(),
            hide_input: Default::default(),
            mask_input: Default::default(),
            drop_input: Default::default(),
        }
    }

    fn add_id(&mut self, n: usize, list: &mut Vec<u16>) {
        if let Ok(v) = parse_id(&self.input[n]) {
            list.push(v);
            Settings::normalize(list);
            self.input[n].clear();
        }
    }

    fn list_editor(
        ui: &mut egui::Ui,
        title: &str,
        input: &mut String,
        list: &mut Vec<u16>,
        mut remove: Option<&mut bool>,
    ) {
        ui.group(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(title).strong());
                    ui.add(egui::TextEdit::singleline(input).hint_text("id / 0xNNN"));
                    if ui.button("Add").clicked() {
                        if let Ok(v) = parse_id(input) {
                            list.push(v);
                            Settings::normalize(list);
                            input.clear();
                        }
                    }
                    if let Some(remove) = &mut remove {
                        **remove = ui.button("x").clicked();
                    }
                });

                let mut remove = None;
                for (i, id) in list.iter().copied().enumerate() {
                    let label = format_id(id);
                    if ui.button(format!("× {label}")).clicked() {
                        remove = Some(i);
                    }
                }
                if let Some(i) = remove {
                    list.remove(i);
                }
            });
        });
    }

    fn controls(&mut self, ui: &mut egui::Ui) {
        let mut settings = self.state.settings.lock().clone();

        self.mask_input.resize(settings.mask.len(), String::new());
        self.drop_input.resize(settings.drop.len(), String::new());
        self.hide_input.resize(settings.hide.len(), String::new());

        ui.heading("Packet filters");
        ui.separator();

        
        egui::Grid::new("filter_grid")
            .num_columns(2)
            .spacing([6.0, 8.0])
            .show(ui, |ui| {                
                Self::list_editor(ui, "Collapse", &mut self.input[1], &mut settings.collapse, None);
                ui.end_row();
                Self::list_editor(ui, "Highlight", &mut self.input[2], &mut settings.highlight, None);
                ui.end_row();

                let mut multilist = |lists: &mut Vec<(Vec<u16>, bool)>, inputs: &mut Vec<String>, pref: &str| {
                    let mut rem_idx = None;
                    for (idx, (drop, _)) in lists.iter_mut().enumerate() {
                        let mut remove = false;
                        Self::list_editor(
                            ui,
                            &format!("{pref} {idx}"),
                            &mut inputs[idx],
                            drop,
                            Some(&mut remove),
                        );
                        if remove {
                            rem_idx = Some(idx);
                        }
                        ui.end_row();
                    }
                    if let Some(idx) = rem_idx {
                        lists.remove(idx);
                        inputs.remove(idx);
                    }
                    if ui.button(format!("Add {pref}")).clicked() {
                        lists.push((Vec::new(), false));
                    }
                    ui.end_row();
                };

                multilist(&mut settings.hide, &mut self.hide_input, "HIDE");
                multilist(&mut settings.mask, &mut self.mask_input, "MASK");
                multilist(&mut settings.drop, &mut self.drop_input, "DROP");
            });

        ui.separator();
        for (idx, (_, en)) in settings.hide.iter_mut().enumerate() {
            ui.checkbox(en, format!("HIDE {idx} Enable"));
        }
        ui.separator();
        for (idx, (_, en)) in settings.mask.iter_mut().enumerate() {
            ui.checkbox(en, format!("MASK {idx} Enable"));
        }
        ui.separator();
        for (idx, (_, en)) in settings.drop.iter_mut().enumerate() {
            ui.checkbox(en, format!("DROP {idx} Enable"));
        }

        ui.separator();
        ui.horizontal(|ui| {
            ui.checkbox(&mut settings.paused, "Pause capture");
            if ui.button("Clear packets").clicked() {
                self.packets.clear();
            }
            if ui.button("Copy all").clicked() {
                let mut text = String::new();
                for packet in &self.packets {
                    if settings.should_show(packet.packet.id) {
                        text.push_str("\n--- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
                        text.push_str(&packet.packet.format_log());
                    }
                }
                ui.output_mut(|o| o.commands.push(OutputCommand::CopyText(text)));
            }
            if ui.button("Save settings").clicked() {
                settings.normalize_all();
                settings.save();
            }
        });
        ui.label(format!("Settings: {}", Settings::path().display()));

        *self.state.settings.lock() = settings;
    }

    fn packet_list(&mut self, ui: &mut egui::Ui) {
        let settings = self.state.settings.lock().clone();

        while let Ok(event) = self.state.rx.try_recv() {
            if !settings.paused {
                self.packets.push_back(event);
                if self.packets.len() > CLEAR_THRESHOLD {
                    for _ in 0..CLEAR_COUNT {
                        self.packets.pop_front();
                    }
                }
            }
        }

        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for event in self.packets.iter_mut() {
                    let id = event.packet.id;
                    if !settings.should_show(id) {
                        continue;
                    }

                    let collapsed = Settings::contains(&settings.collapse, id);
                    let highlighted = Settings::contains(&settings.highlight, id);
                    let name = event.packet.name.as_deref().unwrap_or("packet").to_string();
                    let dir = match event.packet.source {
                        PacketSource::Client => "Client",
                        PacketSource::Server => "Server",
                    };

                    // Packet header
                    ui.horizontal(|ui| {
                        let header = format!(
                            "[{dir}] {} {id:#X} ({id}) {} bytes{}{}",
                            name,
                            event.packet.length,
                            if event.packet.compressed { " COMPRESSED" } else { "" },
                            if event.dropped { " DROPPED" } else { "" },
                        );

                        let response = ui.selectable_label(
                            event.packet.pretty,
                            if event.dropped {
                                egui::RichText::new(header).strong().color(Color32::RED)
                            } else if highlighted {
                                egui::RichText::new(header).strong().color(Color32::GREEN)
                            } else if collapsed {
                                egui::RichText::new(header).strong()
                            } else {
                                egui::RichText::new(header)
                            },
                        );

                        // Format packet as text 
                        if ui.button("Copy").clicked() {
                            let text = event.packet.format_log();
                            ui.output_mut(|o| o.commands.push(OutputCommand::CopyText(text)));
                        };

                        if response.clicked() {
                            event.packet.redissect(!event.packet.pretty);
                        }
                    });

                    // Packet body
                    if event.packet.pretty || !collapsed && event.packet.data.len() > 2 {
                        ui.indent(format!("packet-{id}-{}", event.packet.length), |ui| {
                            ui.monospace(&event.packet.text);
                        });
                    }
                    ui.separator();
                }
            });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(50));

        egui::SidePanel::left("controls")
            .resizable(true)
            .default_width(430.0)
            .show(ctx, |ui| self.controls(ui));

        egui::CentralPanel::default().show(ctx, |ui| self.packet_list(ui));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.state.settings.lock().save();
    }
}

fn parse_id(s: &str) -> Result<u16, ()> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        s.parse::<u16>().map_err(|_| ())
    }
}

fn format_id(id: u16) -> String {
    let name = crate::packet_view::packet_name(id).unwrap_or_else(|| "UNKNOWN".into());
    format!("{name} ({id:#X})")
}

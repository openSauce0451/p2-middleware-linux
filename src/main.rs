#![cfg_attr(windows, windows_subsystem = "windows")]
use eframe::egui::{self, Color32, RichText};
use p2_bridge_core::gateway::Authorization;
use p2_middleware::{
    approval::{ApprovalEvent, PendingApproval},
    bridge::{launch_error_message, Bridge},
    config::Settings,
    network::{self, Adapter},
    RouteClient,
};
use std::{
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};
const GREEN: Color32 = Color32::from_rgb(34, 160, 80);
const RED: Color32 = Color32::from_rgb(210, 50, 50);
const AMBER: Color32 = Color32::from_rgb(220, 150, 20);
const GRAY: Color32 = Color32::from_rgb(150, 150, 150);
fn status(ui: &mut egui::Ui, color: Color32, name: &str, value: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 6.0, color);
        ui.label(RichText::new(name).strong());
        ui.label(value);
    });
}
struct App {
    settings: Settings,
    adapters: Vec<Adapter>,
    selected: Option<u32>,
    discovery: Option<Receiver<Result<Vec<Adapter>, String>>>,
    approval: Option<PendingApproval>,
    cancelling: bool,
    authorization: Option<Authorization>,
    qr: Option<egui::TextureHandle>,
    bridge: Option<Bridge>,
    route: Option<RouteClient>,
    confirmed: bool,
    applying: bool,
    closing: bool,
    close_failed: bool,
    notice: String,
    steam_failed: bool,
    gateway_failed: bool,
    smoke_deadline: Option<Instant>,
}
impl App {
    fn new(cc: &eframe::CreationContext<'_>, smoke: bool) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        cc.egui_ctx.set_style(style);
        let mut app = Self {
            settings: Settings::load().unwrap_or_default(),
            adapters: vec![],
            selected: None,
            discovery: None,
            approval: None,
            cancelling: false,
            authorization: None,
            qr: None,
            bridge: None,
            route: None,
            confirmed: false,
            applying: false,
            closing: false,
            close_failed: false,
            notice: String::new(),
            steam_failed: false,
            gateway_failed: false,
            smoke_deadline: smoke.then(|| Instant::now() + Duration::from_secs(15)),
        };
        app.discover();
        // Explicit smoke mode never requests elevation or performs network cleanup.
        if !smoke {
            app.start_session();
        }
        app
    }
    fn note(&mut self, text: impl Into<String>) {
        self.notice = text.into();
    }
    fn start_session(&mut self) {
        match RouteClient::session() {
            Ok(route) => {
                self.route = Some(route);
                self.note(
                    "Cleaning up the app's previous network settings. Approve Windows if prompted.",
                );
            }
            Err(e) => self.note(launch_error_message(&e)),
        }
    }
    fn discover(&mut self) {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ =
                tx.send(network::adapters().map_err(|_| {
                    "Could not detect the home network. Check the PC connection.".into()
                }));
        });
        self.discovery = Some(rx);
    }
    fn stop_bridge(&mut self) {
        self.confirmed = false;
        self.applying = false;
        if let Some(mut bridge) = self.bridge.take() {
            bridge.stop();
        }
    }
    fn reset(&mut self) {
        self.stop_bridge();
        if let Some(route) = &mut self.route {
            route.reset();
        }
    }
    fn forget(&mut self) {
        self.reset();
        self.authorization = None;
        self.qr = None;
        if let Some(pending) = &self.approval {
            pending.cancel();
            self.cancelling = true;
        }
    }
    fn approve(&mut self) {
        self.cancelling = false;
        self.steam_failed = false;
        self.approval = Some(PendingApproval::start());
        self.note("Scan the Steam Guard code to connect your account.");
    }
    fn confirm(&mut self) {
        let chosen = network::for_console(&self.adapters, &self.settings.ps3_ip)
            .ok()
            .or_else(|| {
                self.adapters
                    .iter()
                    .find(|a| Some(a.index) == self.selected)
            });
        let Some(adapter) = chosen else {
            self.note("Enter a valid PS3 address and select its home network if needed.");
            return;
        };
        self.settings.pc_ip = adapter.address.clone();
        self.settings.router_ip = adapter.gateway.clone();
        self.settings.prefix_len = adapter.prefix;
        if let Err(e) = self.settings.validate() {
            self.note(e);
            return;
        }
        if self.settings.save().is_err() {
            self.note("Could not save the PS3 address.");
            return;
        }
        self.confirmed = true;
        self.gateway_failed = false;
        if self.authorization.is_none() && self.approval.is_none() {
            self.approve();
        }
    }
    fn begin_close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.close_failed = false;
        self.stop_bridge();
        self.authorization = None;
        self.qr = None;
        if let Some(pending) = &self.approval {
            pending.cancel();
            self.cancelling = true;
        }
        if let Some(route) = &mut self.route {
            route.request_stop();
        }
        self.note("Cleaning up before closing...");
    }
    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(result) = self.discovery.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.discovery = None;
            match result {
                Ok(a) => self.adapters = a,
                Err(e) => self.note(e),
            }
        }
        let events: Vec<_> = self
            .approval
            .as_ref()
            .map(|p| p.events.try_iter().collect())
            .unwrap_or_default();
        for event in events {
            match event {
                ApprovalEvent::Challenge(url) if !self.cancelling && !self.closing => {
                    match qr_image(&url) {
                        Ok(image) => {
                            self.qr = Some(ctx.load_texture(
                                "steam-guard",
                                image,
                                egui::TextureOptions::NEAREST,
                            ))
                        }
                        Err(_) => {
                            self.forget();
                            self.note("Could not display Steam Guard. Please retry.");
                        }
                    }
                }
                ApprovalEvent::Challenge(_) => {}
                ApprovalEvent::Complete(result) => {
                    self.approval = None;
                    self.qr = None;
                    if self.cancelling || self.closing {
                        self.cancelling = false;
                    } else {
                        match result {
                            Ok(auth) => {
                                self.authorization = Some(auth);
                                self.note("Steam approved.");
                            }
                            Err(e) => {
                                self.confirmed = false;
                                self.steam_failed = true;
                                self.note(e);
                            }
                        }
                    }
                }
            }
        }
        let events: Vec<_> = self
            .route
            .as_ref()
            .map(|r| r.events.try_iter().collect())
            .unwrap_or_default();
        for message in events {
            self.note(message);
        }
        match self.route.as_mut().map(|r| r.finished()) {
            Some(Ok(Some(success))) => {
                self.route = None;
                self.stop_bridge();
                if !success {
                    self.close_failed = self.closing;
                    self.closing = false;
                }
                // Preserve the specific error rather than replacing it with a generic failure.
                if success {
                    self.note("App network settings cleaned up.");
                }
            }
            Some(Err(_)) => {
                self.route = None;
                self.stop_bridge();
                self.close_failed = self.closing;
                self.closing = false;
                self.note("Lost the network helper. Cleanup could not be confirmed. Retry to finish cleanup.");
            }
            _ => {}
        }
        let events: Vec<_> = self
            .bridge
            .as_ref()
            .map(|b| b.events.try_iter().collect())
            .unwrap_or_default();
        for message in events {
            self.note(message);
        }
        if self
            .bridge
            .as_mut()
            .is_some_and(|b| !matches!(b.finished(), Ok(false)))
        {
            self.reset();
            self.gateway_failed = true;
            self.note("Bridge stopped. Network settings restored.");
        }
        if self.applying && self.route.as_ref().is_some_and(|r| r.clean()) {
            self.stop_bridge();
        }
        if self.confirmed
            && !self.closing
            && self.authorization.is_some()
            && self.bridge.is_none()
            && self.route.as_ref().is_some_and(|r| r.clean())
        {
            match Bridge::start(&self.settings, self.authorization.as_ref().unwrap()) {
                Ok(b) => {
                    self.bridge = Some(b);
                    self.note("Connecting the gateway...");
                }
                Err(e) => {
                    self.confirmed = false;
                    self.gateway_failed = true;
                    self.note(launch_error_message(&e));
                }
            }
        }
        if self.confirmed && !self.applying && self.bridge.as_ref().is_some_and(|b| b.ready()) {
            let index = self
                .adapters
                .iter()
                .find(|a| a.address == self.settings.pc_ip)
                .map(|a| a.index)
                .unwrap_or(0);
            match self
                .route
                .as_mut()
                .ok_or(())
                .and_then(|r| r.apply(self.settings.clone(), index).map_err(|_| ()))
            {
                Ok(()) => self.applying = true,
                Err(_) => {
                    self.reset();
                    self.gateway_failed = true;
                    self.note("Could not apply network settings.");
                }
            }
        }
    }
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        ctx.request_repaint_after(Duration::from_millis(100));
        if ctx.input(|i| i.viewport().close_requested())
            || self.smoke_deadline.is_some_and(|d| Instant::now() >= d)
        {
            self.begin_close();
        }
        if self.closing {
            if self.route.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        } else if self.close_failed {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        let active = self.route.as_ref().is_some_and(|r| r.active());
        let clean = self.route.as_ref().is_some_and(|r| r.clean());
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("P2 middleware");
            ui.add_space(4.0);
            let (color, value) = if self.closing {
                (AMBER, "Cleaning up")
            } else if active || clean {
                (GREEN, "Ready")
            } else if self.route.is_some() {
                (AMBER, "Starting")
            } else {
                (RED, "Stopped")
            };
            status(ui, color, "Network helper", value);
            let (color, value) = if self.authorization.is_some() {
                (GREEN, "Signed in")
            } else if self.approval.is_some() {
                (AMBER, "Waiting for approval")
            } else if self.steam_failed {
                (RED, "Sign-in failed")
            } else {
                (GRAY, "Signed out")
            };
            status(ui, color, "Steam", value);
            let (color, value) = if active {
                (GREEN, "Active")
            } else if self.confirmed {
                (AMBER, "Connecting")
            } else if self.gateway_failed {
                (RED, "Failed")
            } else {
                (GRAY, "Off")
            };
            status(ui, color, "Gateway", value);
            if !self.notice.is_empty() {
                ui.small(&self.notice);
            }
            if self.route.is_none() && !self.closing && ui.button("Retry").clicked() {
                self.close_failed = false;
                self.start_session();
            }
            ui.separator();
            ui.label("PS3 gateway");
            ui.label(
                RichText::new(if active {
                    self.settings.pc_ip.as_str()
                } else {
                    "—"
                })
                .size(28.0)
                .strong()
                .color(if active { GREEN } else { GRAY }),
            );
            ui.small("Set this as the PS3's gateway while the app is open. Restore it afterwards.");
            ui.separator();
            ui.label("PS3 IP address");
            ui.small("PS3: Settings → Network Settings → Settings and Connection Status List.");
            ui.add_enabled_ui(clean && !self.confirmed && !self.closing, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.settings.ps3_ip).desired_width(180.0),
                    );
                    if ui.button("Confirm").clicked() {
                        self.confirm();
                    }
                });
                if network::for_console(&self.adapters, &self.settings.ps3_ip).is_err()
                    && self.adapters.len() > 1
                {
                    egui::ComboBox::from_id_salt("adapter")
                        .selected_text(
                            self.selected
                                .and_then(|id| self.adapters.iter().find(|a| a.index == id))
                                .map(|a| a.name.as_str())
                                .unwrap_or("Select home network"),
                        )
                        .show_ui(ui, |ui| {
                            for a in &self.adapters {
                                ui.selectable_value(
                                    &mut self.selected,
                                    Some(a.index),
                                    format!("{} ({})", a.name, a.address),
                                );
                            }
                        });
                }
            });
            if self.confirmed && ui.button("Disconnect").clicked() {
                self.reset();
            }
            ui.separator();
            ui.label("Steam account");
            if let Some(qr) = &self.qr {
                ui.add(egui::Image::new(qr).fit_to_exact_size(egui::vec2(200.0, 200.0)));
                ui.small("Steam app → Steam Guard → Scan QR code");
            }
            ui.horizontal(|ui| {
                if let Some(auth) = &self.authorization {
                    ui.label(auth.account_name.as_str());
                    if ui.button("Forget").clicked() {
                        self.forget();
                    }
                } else if self.approval.is_some() {
                    if ui.button("Cancel").clicked() {
                        self.forget();
                    }
                } else if ui
                    .add_enabled(!self.closing, egui::Button::new("Sign in"))
                    .clicked()
                {
                    self.approve();
                }
            });
        });
    }
}
impl Drop for App {
    fn drop(&mut self) {
        self.stop_bridge();
        if let Some(route) = &mut self.route {
            route.request_stop();
        }
        if let Some(pending) = &self.approval {
            pending.cancel();
        }
    }
}
include!("qr_image.rs");
fn main() -> eframe::Result {
    let smoke = std::env::args().any(|s| s == "--smoke-test");
    eframe::run_native(
        "P2 middleware",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([420.0, 600.0])
                .with_min_inner_size([380.0, 480.0]),
            renderer: eframe::Renderer::Glow,
            ..Default::default()
        },
        Box::new(move |cc| Ok(Box::new(App::new(cc, smoke)))),
    )
}

mod gui;

use eframe::egui;
use env_logger;

fn main() -> Result<(), eframe::Error> {
    // Enable logging for native windows
    env_logger::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Packet Sniffer",
        options,
        Box::new(|cc| Box::new(gui::PacketSnifferApp::new(cc)))
    )
}

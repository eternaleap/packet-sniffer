use eframe::egui;
use pcap::{Device, Capture};
use std::sync::{Arc, Mutex};
use std::thread;
use chrono::Local;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender, Receiver};

pub struct PacketSnifferApp {
    devices: Vec<Device>,
    selected_device: Option<String>,
    log_text: Arc<Mutex<String>>,
    is_capturing: Arc<AtomicBool>,
    capture_handle: Option<thread::JoinHandle<()>>,
    status_message: String,
    packet_count: Arc<Mutex<usize>>,
    packets_per_second: Arc<Mutex<usize>>,
    last_packet_time: Arc<Mutex<std::time::Instant>>,
    log_update_receiver: Option<Receiver<()>>,
    log_update_sender: Option<Sender<()>>,
}

impl PacketSnifferApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let devices = Device::list().unwrap_or_default();
        let (tx, rx) = channel();
        
        Self {
            devices,
            selected_device: None,
            log_text: Arc::new(Mutex::new(String::new())),
            is_capturing: Arc::new(AtomicBool::new(false)),
            capture_handle: None,
            status_message: String::from("Ready"),
            packet_count: Arc::new(Mutex::new(0)),
            packets_per_second: Arc::new(Mutex::new(0)),
            last_packet_time: Arc::new(Mutex::new(std::time::Instant::now())),
            log_update_sender: Some(tx),
            log_update_receiver: Some(rx),
        }
    }

    fn start_capture(&mut self) {
        if self.is_capturing.load(Ordering::SeqCst) {
            self.status_message = "Already capturing".to_string();
            return;
        }

        let device_name = match &self.selected_device {
            Some(name) => name.clone(),
            None => {
                self.status_message = "No device selected".to_string();
                return;
            }
        };

        let device = match self.devices.iter().find(|d| d.name == device_name) {
            Some(d) => d.clone(),
            None => {
                self.status_message = "Device not found".to_string();
                return;
            }
        };

        let is_capturing = self.is_capturing.clone();
        let log_text = self.log_text.clone();
        let packet_count = self.packet_count.clone();
        let packets_per_second = self.packets_per_second.clone();
        let last_packet_time = self.last_packet_time.clone();
        let log_update_sender = self.log_update_sender.clone();

        self.capture_handle = Some(thread::spawn(move || {
            let cap = match Capture::from_device(device)
                .unwrap()
                .immediate_mode(true)
                .snaplen(65535)
                .open() {
                    Ok(cap) => cap,
                    Err(e) => {
                        let mut log = log_text.lock().unwrap();
                        log.push_str(&format!("Error opening device: {}\n", e));
                        if let Some(sender) = log_update_sender {
                            sender.send(()).ok();
                        }
                        return;
                    }
                };

            let mut capture = cap;
            let mut last_stats_time = std::time::Instant::now();
            let mut packets_since_last_stats = 0;

            while is_capturing.load(Ordering::SeqCst) {
                match capture.next_packet() {
                    Ok(packet) => {
                        // Update packet count
                        {
                            let mut count = packet_count.lock().unwrap();
                            *count += 1;
                            packets_since_last_stats += 1;
                        }

                        // Update last packet time and calculate PPS
                        {
                            let now = std::time::Instant::now();
                            *last_packet_time.lock().unwrap() = now;

                            if now.duration_since(last_stats_time).as_secs() >= 1 {
                                *packets_per_second.lock().unwrap() = packets_since_last_stats;
                                packets_since_last_stats = 0;
                                last_stats_time = now;
                            }
                        }

                        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
                        let mut log_entry = format!("\n[{}] Packet Length: {} bytes\n", timestamp, packet.header.len);

                        if let Ok(eth_packet) = etherparse::SlicedPacket::from_ethernet(&packet) {
                            // Link Layer
                            if let Some(etherparse::LinkSlice::Ethernet2(eth)) = eth_packet.link {
                                log_entry.push_str(&format!("MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} -> {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}\n",
                                    eth.source()[0], eth.source()[1], eth.source()[2], eth.source()[3], eth.source()[4], eth.source()[5],
                                    eth.destination()[0], eth.destination()[1], eth.destination()[2], eth.destination()[3], eth.destination()[4], eth.destination()[5]));
                            }

                            // Network Layer
                            if let Some(ip) = eth_packet.ip {
                                match ip {
                                    etherparse::InternetSlice::Ipv4(header, _) => {
                                        log_entry.push_str(&format!("IPv4: {} -> {}\n",
                                            header.source_addr(),
                                            header.destination_addr()));
                                    }
                                    etherparse::InternetSlice::Ipv6(header, _) => {
                                        log_entry.push_str(&format!("IPv6: {} -> {}\n",
                                            header.source_addr(),
                                            header.destination_addr()));
                                    }
                                }
                            }

                            // Transport Layer
                            if let Some(transport) = eth_packet.transport {
                                match transport {
                                    etherparse::TransportSlice::Tcp(tcp) => {
                                        log_entry.push_str(&format!("TCP: {}:{} -> {}:{}\n",
                                            tcp.source_port(),
                                            tcp.destination_port(),
                                            tcp.sequence_number(),
                                            tcp.acknowledgment_number()));
                                    }
                                    etherparse::TransportSlice::Udp(udp) => {
                                        log_entry.push_str(&format!("UDP: {} -> {}\n",
                                            udp.source_port(),
                                            udp.destination_port()));
                                    }
                                    etherparse::TransportSlice::Icmpv4(icmp) => {
                                        log_entry.push_str(&format!("ICMP Type: {:?}\n",
                                            icmp.icmp_type()));
                                    }
                                    etherparse::TransportSlice::Icmpv6(icmp) => {
                                        log_entry.push_str(&format!("ICMPv6 Type: {:?}\n",
                                            icmp.icmp_type()));
                                    }
                                    etherparse::TransportSlice::Unknown(protocol) => {
                                        log_entry.push_str(&format!("Unknown Protocol: {}\n",
                                            protocol));
                                    }
                                }
                            }

                            log_entry.push_str("----------------------------------------\n");
                        }

                        let mut log = log_text.lock().unwrap();
                        log.push_str(&log_entry);
                        if let Some(sender) = &log_update_sender {
                            sender.send(()).ok();
                        }
                    }
                    Err(e) => {
                        if !is_capturing.load(Ordering::SeqCst) {
                            break;
                        }
                        thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
        }));

        self.is_capturing.store(true, Ordering::SeqCst);
        self.status_message = "Capturing started".to_string();
    }

    fn stop_capture(&mut self) {
        self.is_capturing.store(false, Ordering::SeqCst);
        if let Some(handle) = self.capture_handle.take() {
            handle.join().ok();
        }
        self.status_message = "Capture stopped".to_string();
    }

    fn save_log(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Text Files", &["txt"])
            .save_file() {
                if let Err(e) = std::fs::write(&path, &*self.log_text.lock().unwrap()) {
                    self.status_message = format!("Error saving file: {}", e);
                } else {
                    self.status_message = "Log saved successfully".to_string();
                }
            }
    }
}

impl eframe::App for PacketSnifferApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("List Interfaces").clicked() {
                    self.devices = Device::list().unwrap_or_default();
                }

                if !self.is_capturing.load(Ordering::SeqCst) {
                    if ui.button("Start Capture").clicked() {
                        self.start_capture();
                    }
                } else {
                    if ui.button("Stop Capture").clicked() {
                        self.stop_capture();
                    }
                }

                if ui.button("Clear Log").clicked() {
                    let mut log = self.log_text.lock().unwrap();
                    log.clear();
                    *self.packet_count.lock().unwrap() = 0;
                }

                if ui.button("Save Log").clicked() {
                    self.save_log();
                }
            });

            ui.horizontal(|ui| {
                ui.label("Select Interface:");
                egui::ComboBox::from_label("")
                    .selected_text(self.selected_device.as_deref().unwrap_or("Select..."))
                    .show_ui(ui, |ui| {
                        for device in &self.devices {
                            let text = format!("{} ({})", 
                                device.name,
                                device.desc.as_deref().unwrap_or("No description"));
                            ui.selectable_value(
                                &mut self.selected_device,
                                Some(device.name.clone()),
                                text
                            );
                        }
                    });
            });

            // Add statistics display
            ui.horizontal(|ui| {
                let count = *self.packet_count.lock().unwrap();
                let pps = *self.packets_per_second.lock().unwrap();
                ui.label(format!("Total Packets: {} | Packets/sec: {}", count, pps));
            });

            ui.label(&self.status_message);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Check for log updates
            if let Some(receiver) = &self.log_update_receiver {
                while receiver.try_recv().is_ok() {
                    // Update received, will redraw the text area
                }
            }

            let text_style = egui::TextStyle::Monospace;
            let font_id = ui.style().text_styles.get(&text_style).unwrap().clone();
            
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    let log_text = self.log_text.lock().unwrap();
                    ui.add(
                        egui::TextEdit::multiline(&mut log_text.as_str())
                            .font(font_id)
                            .desired_width(f32::INFINITY)
                            .desired_rows(30)
                            .lock_focus(true)
                    );
                });
        });

        // Request repaint frequently when capturing
        if self.is_capturing.load(Ordering::SeqCst) {
            ctx.request_repaint();
        }
    }
}

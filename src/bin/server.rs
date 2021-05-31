use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use netbug::config::server::ServerConfig;
use netbug::error::Result;
use netbug::process::PcapProcessor;
use netbug::receiver::Receiver;

fn main() {
    let server_cfg = match ServerConfig::from_path("examples/config/server.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        },
    };

    println!("Starting server...");

    let mut receiver = match Receiver::new(server_cfg.srv_addr, server_cfg.pcap_dir.clone()) {
        Ok(receiver) => receiver,
        Err(err) => {
            eprintln!("Error creating pcap receiver: {}", err.to_string());
            return;
        },
    };

    let _processor = PcapProcessor::new(&server_cfg.behaviors, server_cfg.pcap_dir.to_path_buf());

    loop {
        match receiver.receive() {
            Ok(path) => println!("Received pcap -> {}", path.to_str().unwrap()),
            Err(err) => eprintln!("Error receiving pcap: {}", err.to_string()),
        }
    }

    println!("Stopping server...");
}

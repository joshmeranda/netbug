use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::Duration;

use netbug::config::server::ServerConfig;
use netbug::process::PcapProcessor;
use netbug::error::Result;
use std::path::PathBuf;
use std::net::{TcpListener, SocketAddr, TcpStream};
use threadpool::ThreadPool;
use netbug::receiver::Receiver;

fn run_server(cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.srv_addr)?;
    let pool = ThreadPool::new(cfg.n_workers);

    for conn in listener.incoming() {
        let stream = match conn {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("Error accepting connections: {}", err.to_string());
                break;
            }
        };

        println!("Accepted connection from '{}'", stream.peer_addr().unwrap().to_string());

        // ensure the pcap directory exists before receiving pcaps from the peer
        // todo: might be faster to push and pop the peer addresses from the same PathBuf rather than continuously cloning it
        let mut pcap_dir = cfg.pcap_dir.clone();
        pcap_dir.push(stream.peer_addr().unwrap().to_string());

        if !pcap_dir.exists() {
            if let Err(err) = fs::create_dir_all(&pcap_dir) {
                eprintln!("Error creating pcap directory '{}': {}", pcap_dir.to_str().unwrap(), err.to_string());
            }
        }
    }

    Ok(())
}

fn main() {
    let server_cfg = match ServerConfig::from_path("examples/config/server.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        },
    };

    // let mut server = Server::from(server_cfg);

    println!("Starting server...");

    let mut receiver = match Receiver::new(server_cfg.srv_addr, server_cfg.pcap_dir) {
        Ok(receiver) => receiver,
        Err(err) => {
            eprintln!("Error creating pcap receiver: {}", err.to_string());
            return;
        }
    };

    loop {
        match receiver.receive() {
            Ok(path) => println!("Received pcap -> {}", path.to_str().unwrap()),
            Err(err) => eprintln!("Error receiving pcap: {}", err.to_string()),
        }
    }

    println!("Stopping server...");
}

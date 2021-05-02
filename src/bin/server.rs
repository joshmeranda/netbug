use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::Duration;

use netbug::config::server::ServerConfig;
use netbug::process::PcapProcessor;
use netbug::server::Server;
use std::path::PathBuf;

fn main() {
    let server_cfg = match ServerConfig::from_path("examples/config/server.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        },
    };

    let server = Server::new(server_cfg.srv_addr, server_cfg.n_workers, server_cfg.pcap_dir.clone());
    let processor = PcapProcessor::new(server_cfg.behaviors, server_cfg.pcap_dir);

    if let Err(err) = server.start() {
        eprintln!("Could not start the server: {}", err.to_string());
        return;
    } else {
        println!("Starting server...");
    }

    while server.is_running() {
        let report = processor.process();

        match report {
            Ok(report) => {
                let content = serde_json::to_string_pretty(&report).unwrap();
                let report_dir = &server_cfg.report_dir;

                println!("=== report_dir: {}", report_dir.to_str().unwrap());
                if ! report_dir.exists() {
                    fs::create_dir_all(report_dir);
                }

                let mut report_file = PathBuf::from(report_dir);
                report_file.push("report.json");

                let mut file = match File::create(report_file) {
                    Ok(file) => file,
                    Err(err) => {
                        eprintln!("Error opening report file: {}", err.to_string());
                        continue;
                    },
                };

                if let Err(err) = file.write(content.as_ref()) {
                    eprintln!("Error writing report {}", err.to_string())
                }
            },
            Err(err) => eprintln!("Error processing captures: {}", err.to_string()),
        }

        std::thread::sleep(Duration::from_secs(5));
    }

    println!("Stopping server...");
}

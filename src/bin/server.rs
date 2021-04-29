use netbug::config::server::ServerConfig;
use netbug::server::Server;
use std::time::Duration;
use netbug::process::PcapProcessor;

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
            Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
            Err(err) => eprintln!("Error processing captures: {}", err.to_string())
        }

        std::thread::sleep(Duration::from_secs(5));
    }

    println!("Stopping server...");
}

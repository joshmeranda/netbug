use netbug::config::server::ServerConfig;
use netbug::server::Server;
use std::time::Duration;

fn main() {
    let server_cfg = match ServerConfig::from_path("examples/config/server.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        },
    };

    let server = Server::from_config(server_cfg);

    if let Err(err) = server.start() {
        eprintln!("Could not start the server: {}", err.to_string());
        return;
    } else {
        println!("Starting server...");
    }

    while server.is_running() {
        let report = server.process();

        match report {
            Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
            Err(err) => eprintln!("Error processing captures: {}", err.to_string())
        }

        std::thread::sleep(Duration::from_secs(5));
    }

    println!("Stopping server...");
}

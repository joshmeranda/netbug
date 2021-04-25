use netbug::config::server::ServerConfig;
use netbug::server::Server;

fn main() {
    let server_cfg = match ServerConfig::from_path("examples/config/server.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        },
    };

    let server = Server::from_config(server_cfg);

    // if let Err(err) = server.start() {
    //     eprintln!("Could not start the server: {}", err.to_string());
    //     return;
    // } else {
    //     println!("Starting server...");
    // }

    serde_json::to_string(&server.process().unwrap());

    while server.is_running() {}

    println!("Stopping server...");
}

use netbug::config::server::ServerConfig;
use netbug::server::Server;

fn main() {
    let server_cfg = match ServerConfig::from_path("examples/config/server.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        }
    };

    let server = Server::from_config(server_cfg);

    server.start();
}

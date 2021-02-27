extern crate netbug;

use netbug::client::Client;
use netbug::config::client::ClientConfig;

fn main() {
    let client_cfg = match ClientConfig::from_path("examples/config/client.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        }
    };

    let mut client = Client::from_config(client_cfg);

    if let Err(err) = client.start_capture() {
        eprintln!("{}", err.to_string());
    }

    if let Err(err) = client.run_scripts() {
        eprintln!("{}", err.to_string());
    }

    std::thread::sleep(std::time::Duration::from_secs(5));
}

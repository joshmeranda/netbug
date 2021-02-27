extern crate netbug;

use pcap::{Capture, Device};

use std::sync::{Arc, Mutex};
use std::thread::Builder;
use toml;

use netbug::config::client::ClientConfig;
use netbug::config::error::ConfigError;
use netbug::client::Client;

fn main() {
    let client_cfg = match ClientConfig::from_path("examples/config/client.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return
        }
    };

    let mut client = Client::from_config(client_cfg);

    client.start_capture();

    client.run_scripts();

    std::thread::sleep(std::time::Duration::from_secs(5));
}

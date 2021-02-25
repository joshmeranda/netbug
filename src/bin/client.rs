extern crate config;

use pcap::Device;
use std::sync::{Arc, Mutex};
use std::thread::Builder;
use toml;

use config::client::ClientConfig;
use config::error::ConfigError;

fn main() {
    let client_cfg = match ClientConfig::from_path("examples/config/client.toml") {
        Ok(cfg) => cfg,
        Err(ConfigError::Io(err)) => {
            eprintln!("Error opening config file: {}", err.to_string());
            return;
        }
        Err(ConfigError::Toml(err)) => {
            eprintln!("Error parsing config: {}", err.to_string());
            return;
        }
    };

    let capture_flag = Arc::new(Mutex::new(true));
    let devices = vec![Device::lookup().unwrap()];

    // keeps track that at least one interface has started a packet capture
    let mut capture_started = false;

    for device in devices {
        let flag = Arc::clone(&capture_flag);
        let device_name = String::from(device.name.clone());
        let capture_result = device.open();

        println!("=== 000 {} ===", device_name);

        match capture_result {
            Ok(mut capture) => {
                let mut save_file = capture.savefile(format!("{}.pcap", &device_name)).unwrap();

                let builder = Builder::new().name(device_name);

                // todo: check that the thread was started successfully
                // todo: add timestamp to end pf pcap name
                builder.spawn(move || loop {
                    let packet = capture.next();

                    if packet.is_ok() {
                        save_file.write(&packet.unwrap());
                    }

                    if !*flag.lock().unwrap() {
                        break;
                    }
                });

                capture_started = true;
            }
            Err(err) => {
                eprintln!(
                    "Unable to create a capture for device '{}'\n{}",
                    device_name,
                    err.to_string()
                )
            }
        }
    }

    if capture_started {
        client_cfg.run_scripts();
    }

    *capture_flag.lock().unwrap() = false;
}

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

    let client = Client::from_config(client_cfg);

    let capture_flag = Arc::new(Mutex::new(true));

    // find the list of valid devices on which to start a packet capture
    let devices = Device::list().unwrap();
    let devices: Vec<Device> = devices
        .into_iter()
        .filter(|device| {
            client_cfg.interfaces.contains(&device.name)
        })
        .collect();

    // keeps track that at least one interface has started a packet capture
    let mut capture_started = false;

    for device in devices {
        let flag = Arc::clone(&capture_flag);
        let device_name = String::from(device.name.clone());
        let capture_result = device.open();

        match capture_result {
            Ok(mut capture) => {

                let mut save_file = capture
                    .savefile(format!("{}.pcap", &device_name)).unwrap();

                let builder = Builder::new().name(device_name.clone());

                // todo: check that the thread was started successfully
                // todo: add timestamp to end pf pcap name
                let handle = builder.spawn(move || while *flag.lock().unwrap() {
                    let packet = capture.next();

                    if packet.is_ok() {
                        save_file.write(&packet.unwrap());
                    }
                });

                match handle {
                    Ok(_) => println!("Started capture for device '{}'", device_name),
                    Err(err) => println!("Err: {}", err.to_string())
                }

                capture_started = true;;
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
        // client_cfg.run_scripts();

        // give the captures some time to read all packets from buffer
        // todo: make configurable
        std::thread::sleep(std::time::Duration::new(10, 0));
    }

    *capture_flag.lock().unwrap() = false;
}

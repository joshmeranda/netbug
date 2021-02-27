use std::process::{Child, Command};
use std::path::{PathBuf, Path};
use std::io;
use std::default::Default;

use crate::config::client::ClientConfig;
use crate::config::defaults;
use pcap::Device;
use std::thread::{Builder, JoinHandle};
use std::sync::Arc;

#[derive(Default)]
pub struct Client {
    script_dir: PathBuf,

    allow_concurrent: bool,

    devices: Vec<Device>,

    capture_handles: Vec<JoinHandle<()>>
}

impl Client {
    pub fn new() -> Client {
        Client::default()
    }

    /// Construct a client from the client configuration
    pub fn from_config(cfg: ClientConfig) -> Client {
        // find the list of valid devices on which to start a packet capture
        let devices = Device::list().unwrap();
        let devices: Vec<Device> = devices
            .into_iter()
            .filter(|device| {
                cfg.interfaces.contains(&device.name)
            })
            .collect();

        Client {
            script_dir: cfg.script_dir,
            allow_concurrent: cfg.allow_concurrent,
            devices,
            .. Client::default()
        }
    }

    /// Run all scripts found in the configured scrip directory and block until all are complete
    /// todo: consider replacing with Runner struct
    pub fn run_scripts(&self) -> Result<(), io::Error> {
        let mut children: Vec<Child> = vec![]; // will not always be used

        for entry in self.script_dir.read_dir()? {
            let entry = entry?;
            let path = entry.path();
            let child = Command::new(path.to_str().unwrap()).spawn();

            if let Err(err) = child {
                eprintln!(
                    "Couldn't execute script at '{}': {}",
                    path.to_str().unwrap(),
                    err.to_string()
                );
                break;
            };

            let mut child = child.unwrap();

            if self.allow_concurrent {
                child.wait();
            } else {
                children.push(child);
            }
        }

        if !children.is_empty() {
            for mut child in children {
                child.wait();
            }
        }

        Ok(())
    }

    pub fn start_capture(&mut self) -> Result<(), ()> {
        // todo: fix Error types
        for device in &self.devices {
            let device_name = String::from(device.name.clone());
            let capture_result = device.clone().open();

            match capture_result {
                Ok(mut capture) => {

                    let mut save_file = capture
                        .savefile(format!("{}.pcap", &device_name)).unwrap();

                    let builder = Builder::new().name(device_name.clone());

                    // todo: check that the thread was started successfully
                    // todo: add timestamp to end pf pcap name
                    let handle = builder
                        .spawn(move || loop {
                            let packet = capture.next();

                            if packet.is_ok() {
                                save_file.write(&packet.unwrap());
                            }
                        });

                    match handle {
                        Ok(handle) => {
                            self.capture_handles.push(handle);
                            println!("Started capture for device '{}'", device_name)
                        },
                        Err(err) => println!("Err: {}", err.to_string())
                    }
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

        Ok(())
    }

    pub fn transfer_pcaps(&self) {
        todo!("transfer all pcap files in self.pcap_dir to the remote (or local) analysis server")
    }
}
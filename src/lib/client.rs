use std::default::Default;
use std::io;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::thread::Builder;

use pcap::Device;

use crate::config::client::ClientConfig;
use crate::error::ClientError;

#[derive(Default)]
pub struct Client {
    script_dir: PathBuf,

    allow_concurrent: bool,

    devices: Vec<Device>,
}

impl Client {
    pub fn new() -> Client {
        Client::default()
    }

    /// Construct a client from a [ClientConfig] which is consumed.
    pub fn from_config(cfg: ClientConfig) -> Client {
        // find the list of valid devices on which to start a packet capture
        let devices = Device::list().unwrap();
        let devices: Vec<Device> = devices
            .into_iter()
            .filter(|device| cfg.interfaces.contains(&device.name))
            .collect();

        Client {
            script_dir: cfg.script_dir,
            allow_concurrent: cfg.allow_concurrent,
            devices,
            ..Client::default()
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

    /// Begin capturing packets on the configured network devices. Note that there is currently no
    /// way to stop the capture once it begins, so take care to ensure that you start it as late as
    /// possible to avoid needlessly capturing  packets..
    pub fn start_capture(&mut self) -> Result<(), ClientError> {
        // todo: fix Error types
        for device in &self.devices {
            let device_name = String::from(device.name.clone());
            let mut capture = device.clone().open()?;

            let mut save_file = capture.savefile(format!("{}.pcap", &device_name)).unwrap();

            let builder = Builder::new().name(device_name.clone());

            // todo: check that the thread was started successfully
            // todo: add timestamp to end pf pcap name
            builder.spawn(move || loop {
                let packet = capture.next();

                if packet.is_ok() {
                    save_file.write(&packet.unwrap());
                }
            })?;

            println!("Started capture for device '{}'", device_name)
        }

        Ok(())
    }

    pub fn transfer_pcaps(&self) {
        todo!("transfer all pcap files in self.pcap_dir to the remote (or local) analysis server")
    }
}

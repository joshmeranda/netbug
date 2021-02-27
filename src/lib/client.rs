use std::default::Default;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::result;
use std::thread::Builder;

use pcap::{Capture, Device};

use crate::config::client::ClientConfig;
use crate::config::defaults;
use crate::config::defaults::default_concurrent_run;
use crate::error::ClientError;

type Result = result::Result<(), ClientError>;

#[derive(Default)]
pub struct Client {
    script_dir: PathBuf,

    pcap_dir: PathBuf,

    allow_concurrent: bool,

    devices: Vec<Device>,
}

impl Client {
    pub fn new() -> Client {
        Client {
            script_dir: defaults::default_script_dir(),
            pcap_dir: defaults::default_pcaps_dir(),
            allow_concurrent: default_concurrent_run(),
            ..Client::default()
        }
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
            pcap_dir: cfg.pcap_dir,
            allow_concurrent: cfg.allow_concurrent,
            devices,
            ..Client::default()
        }
    }

    /// Run all scripts found in the configured scrip directory and block until all are complete.
    /// todo: consider replacing with Runner struct
    pub fn run_scripts(&self) -> Result {
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

            // if scripts are allowed to run concurrently add to child Vec, else wait to finish before next iteration
            if self.allow_concurrent {
                children.push(child);
            } else {
                // no need to kill other children since all scripts are run concurrently
                child.wait()?;
            }
        }

        if !children.is_empty() {
            for mut child in children {
                child.wait()?;
            }
        }

        Ok(())
    }

    /// Begin capturing packets on the configured network devices. Note that there is currently no
    /// explicit way to end capture and flush its output, be mindful of your client's scoping to
    /// prevent capturing unnecessary packets.
    pub fn start_capture(&mut self) -> Result {
        // ensure that the packet capture directory exists
        if !self.pcap_dir.exists() {
            fs::create_dir(self.pcap_dir.clone())?;
        }

        for device in &self.devices {
            let device_name = String::from(device.name.clone());

            let mut capture = Capture::from_device(device.clone())?
                .timeout(1)
                .open()?
                .setnonblock()?;

            let mut pcap_path = PathBuf::from(&self.pcap_dir);
            pcap_path.push(format!("{}.pcap", &device_name));

            let mut save_file = capture.savefile(pcap_path).unwrap();

            // todo: check that the thread was started successfully
            // todo: add timestamp to end of pcap name
            let builder = Builder::new().name(device_name.clone());
            builder.spawn(move || loop {
                match capture.next() {
                    Ok(packet) => save_file.write(&packet),
                    Err(_) => {} // todo: these errors should be handled
                }

                println!("=== 000 ===");
            })?;

            println!("Started capture for device '{}'", device_name)
        }

        Ok(())
    }

    pub fn transfer_pcaps(&self) {
        todo!("transfer all pcap files in self.pcap_dir to the remote (or local) analysis server")
    }
}

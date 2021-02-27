use std::process::{Child, Command};
use std::path::{PathBuf, Path};
use std::io;

use crate::config::client::ClientConfig;
use crate::config::defaults;

pub struct Client {
    script_dir: PathBuf,

    allow_concurrent: bool,


}

impl Client {
    pub fn new() -> Client {
        Client {
            script_dir: defaults::default_script_dir(),
            allow_concurrent: false
        }
    }

    /// Construct a client from the client configuration
    pub fn from_config(cfg: ClientConfig) -> Client {
        Client {
            script_dir: cfg.script_dir,
            allow_concurrent: cfg.allow_concurrent
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

    pub fn start_capture(&self) -> Result<(), io::Error> {
    }

    pub fn transfer_pcaps(&self) {
        todo!("transfer all pcap files in self.pcap_dir to the remote (or local) analysis server")
    }
}
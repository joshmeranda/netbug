use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::result;

use super::{defaults, error::Error};

pub type Result = result::Result<ClientConfig, Error>;

/// Represents basic client configuration
/// todo: specify pcap backup
/// todo: allow configure the pcap filter
/// todo: configure capture buffer size
#[derive(Deserialize)]
pub struct ClientConfig {
    /// the path to the directory which holds the client test scripts, these scripts should expect
    /// to receive any arguments as they will receive none
    #[serde(default = "defaults::default_script_dir")]
    pub script_dir: PathBuf,

    /// the directory in which to store the pcap generated by the scripts in [script_dir]
    #[serde(default = "defaults::default_pcaps_dir")]
    pub pcap_dir: PathBuf,

    /// allow all scripts to be executed at once rather then one at a time
    #[serde(default = "defaults::default_concurrent_run")]
    pub allow_concurrent: bool,

    /// the amount of delay between scripts and actions are completed and the capture ends [0 - 255],
    /// giving pcap some more time to pull in any lingering network packets.
    #[serde(default = "defaults::default_delay")]
    pub delay: u8,

    pub interfaces: Vec<String>,

    /// the ip or hostname of the end server to send the resulting pcap
    pub srv_addr: Ipv4Addr,

    /// the port to send the pcap to
    pub srv_port: usize,
}

impl ClientConfig {
    pub fn new() -> Result {
        let default_path = defaults::default_config_file_path();

        ClientConfig::from_path(default_path)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result {
        // todo: handle toml parsing error
        // todo: handle config errors
        //   script_dir | pcap_dir is not a dir, etc
        let content = fs::read_to_string(path)?;

        match toml::from_str(content.as_str()) {
            Ok(cfg) => Ok(cfg),
            Err(err) => Err(Error::from(err)),
        }
    }
}

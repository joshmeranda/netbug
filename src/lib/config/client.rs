use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use super::defaults;
use super::error::{ConfigError, Result};
use crate::behavior::Behavior;

/// Represents basic client configuration.
/// todo: specify pcap backup
/// todo: allow configure the pcap filter
/// todo: configure capture buffer size
#[derive(Deserialize)]
pub struct ClientConfig {
    /// The path to the directory which holds the client test scripts, these scripts should expect
    /// to receive any arguments as they will receive none.
    #[serde(default = "defaults::default_script_dir")]
    pub script_dir: PathBuf,

    /// The directory in which to store the pcap generated by the scripts in [script_dir].
    #[serde(default = "defaults::default_pcap_dir")]
    pub pcap_dir: PathBuf,

    /// Allow all scripts to be executed at once rather then one at a time
    #[serde(default = "defaults::client::default_concurrent_run")]
    pub allow_concurrent: bool,

    /// The amount of delay between scripts and actions are completed and the capture ends [0 - 255],
    /// giving pcap some more time to pull in any lingering network packets.
    #[serde(default = "defaults::client::default_delay")]
    pub delay: u8,

    /// The list of network devices names upon which network packets should be captured.
    pub interfaces: Vec<String>,

    /// The host / ip and port pair of the target socket
    pub srv_addr: SocketAddr,

    pub behaviors: Vec<Behavior>,
}

impl ClientConfig {
    pub fn new() -> Result<ClientConfig> {
        let default_path = defaults::default_config_file_path();

        ClientConfig::from_path(default_path)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<ClientConfig> {
        // todo: handle toml parsing error
        // todo: handle config errors
        //   script_dir | pcap_dir is not a dir, etc
        let content = fs::read_to_string(path)?;

        match toml::from_str(content.as_str()) {
            Ok(cfg) => Ok(cfg),
            Err(err) => Err(ConfigError::from(err)),
        }
    }
}

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::behavior::Behavior;
use crate::config::defaults;
use crate::config::error::{ConfigError, Result};

#[derive(Deserialize)]
pub struct ServerConfig {
    /// The directory in which to store the pcap generated by the scripts in
    /// [script_dir].
    #[serde(default = "defaults::default_pcap_dir")]
    pub pcap_dir: PathBuf,

    /// The host / ip and port pair of the target socket.
    pub srv_addr: SocketAddr,

    pub behaviors: Vec<Behavior>,

    #[serde(default = "defaults::server::default_n_workers")]
    pub n_workers: usize,

    #[serde(default = "defaults::default_report_dir")]
    pub report_path: PathBuf,
}

impl ServerConfig {
    pub fn new() -> Result<ServerConfig> {
        let default_path = defaults::default_config_file_path();

        ServerConfig::from_path(default_path)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<ServerConfig> {
        let content = fs::read_to_string(path)?;

        match toml::from_str(content.as_str()) {
            Ok(cfg) => Ok(cfg),
            Err(err) => Err(ConfigError::from(err)),
        }
    }
}

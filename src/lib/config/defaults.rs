/// Provides default values used to generate default configurations
use std::path::PathBuf;

const NETBUG_BASE_DIR: &str = "/etc/nbug.d";

const NETBUG_CONFIG_FILE_NAME: &str = "/etc/conf.toml";

const NETBUG_PCAP_SUB_DIR_NAME: &str = "pcap";

const NETBUG_SCRIPTS_SUB_DIR_NAME: &str = "scripts";

const NETBUG_REPORT_DIR_NAME: &str = "report";

// Common Values
pub fn default_config_file_path() -> PathBuf {
    let mut path = PathBuf::from(NETBUG_BASE_DIR);
    path.push(NETBUG_CONFIG_FILE_NAME);

    path
}

pub fn default_script_dir() -> PathBuf {
    let mut path = PathBuf::from(NETBUG_BASE_DIR);
    path.push(NETBUG_SCRIPTS_SUB_DIR_NAME);

    path
}

pub fn default_pcap_dir() -> PathBuf {
    let mut path = PathBuf::from(NETBUG_BASE_DIR);
    path.push(NETBUG_PCAP_SUB_DIR_NAME);

    path
}

pub fn default_report_dir() -> PathBuf {
    let mut path = PathBuf::from(NETBUG_BASE_DIR);
    path.push(NETBUG_REPORT_DIR_NAME);

    path
}

pub fn default_server_port() -> u16 { 8081 }

// Client Specific Values
pub mod client {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::Addr;

    pub fn default_concurrent_run() -> bool { false }

    pub fn default_delay() -> u8 { 1 }

    pub fn default_addr() -> Addr { Addr::Internet(IpAddr::V4(Ipv4Addr::UNSPECIFIED)) }
}

// Server Specific Values
// todo: calculate the number of sockets / cores / threads on the host machine
pub mod server {
    pub fn default_n_workers() -> usize { 4 }
}
/// Provides default values used to generate default configurations
use std::path::PathBuf;

const NETBUG_BASE_DIR: &str = "/etc/nbug.d";

const NETBUG_CONFIG_FILE_NAME: &str = "conf.toml";

const NETBUG_PCAPS_SUB_DIR_NAME: &str = "pcaps";

const NETBUG_SCRIPTS_SUB_DIR_NAME: &str = "scripts";

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

pub fn default_pcaps_dir() -> PathBuf {
    let mut path = PathBuf::from(NETBUG_BASE_DIR);
    path.push(NETBUG_PCAPS_SUB_DIR_NAME);

    path
}

// Client Specific Values

pub fn default_concurrent_run() -> bool {
    false
}

// Server Specific Values

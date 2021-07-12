use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clokwerk::Interval;
use regex::Regex;
use serde::de::Error;
use serde::{Deserialize, Deserializer};

use super::defaults;
use super::error::{ConfigError, Result};
use crate::behavior::Behavior;
use crate::bpf::filter::FilterExpression;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CaptureInterval(pub Interval);

impl FromStr for CaptureInterval {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self> {
        let re = Regex::new("^([0-9]*)([sSmMhH])$").unwrap();

        match re.captures(s) {
            Some(captures) => {
                let size: u32 = captures.get(1).unwrap().as_str().parse().unwrap();

                let unit = match captures.get(2) {
                    Some(u) => u.as_str(),
                    None => "M",
                };

                match unit {
                    "s" | "S" => Ok(CaptureInterval(Interval::Seconds(size))),
                    "m" | "M" => Ok(CaptureInterval(Interval::Minutes(size))),
                    "h" | "H" => Ok(CaptureInterval(Interval::Hours(size))),
                    _ => Err(ConfigError::Other(format!("Bad interval unit: {}", unit))),
                }
            },
            None => Err(ConfigError::Other(
                format!("could not parse an Interval from the string {}", s).to_owned(),
            )),
        }
    }
}

impl<'de> Deserialize<'de> for CaptureInterval {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>, {
        let s = Deserialize::deserialize(deserializer)?;

        match CaptureInterval::from_str(s) {
            Ok(interval) => Ok(interval),
            Err(err) => Err(<D as Deserializer<'de>>::Error::custom(err.to_string())),
        }
    }
}

/// Represents basic client configuration.
/// todo: specify pcap backup
/// todo: allow configure the pcap filter
/// todo: configure capture buffer size
#[derive(Deserialize)]
pub struct ClientConfig {
    /// The path to the directory which holds the client test scripts, these
    /// scripts should expect to receive any arguments as they will receive
    /// none.
    #[serde(default = "defaults::default_script_dir")]
    pub script_dir: PathBuf,

    /// The directory in which to store the pcap generated by the scripts in
    /// [script_dir].
    #[serde(default = "defaults::default_pcap_dir")]
    pub pcap_dir: PathBuf,

    /// Allow all scripts to be executed at once rather then one at a time
    #[serde(default = "defaults::client::default_concurrent_run")]
    pub allow_concurrent: bool,

    /// The amount of delay between scripts and actions are completed and the
    /// capture ends [0 - 255], giving pcap some more time to pull in any
    /// lingering network packets.
    #[serde(default = "defaults::client::default_delay")]
    pub delay: u8,

    /// The list of network devices names upon which network packets should be
    /// captured.
    pub interfaces: Vec<String>,

    /// The host / ip and port pair of the target socket
    pub srv_addr: SocketAddr,

    pub behaviors: Vec<Behavior>,

    /// If present, the given BPF filter is used when filtering packets. If not
    /// specified netbug will generate its own.
    pub filter: Option<FilterExpression>,

    #[serde(default = "defaults::client::default_interval")]
    pub interval: CaptureInterval,
}

impl ClientConfig {
    pub fn new() -> Result<ClientConfig> {
        let default_path = defaults::default_config_file_path();

        ClientConfig::from_path(default_path)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<ClientConfig> {
        // todo: handle config errors
        //   script_dir | pcap_dir is not a dir, etc
        let content = fs::read_to_string(path)?;

        match toml::from_str(content.as_str()) {
            Ok(cfg) => Ok(cfg),
            Err(err) => Err(ConfigError::from(err)),
        }
    }
}

#[cfg(test)]
mod test {
    use clokwerk::Interval;
    use serde::de::Error;

    use crate::config::client::CaptureInterval;

    #[derive(Deserialize)]
    struct IntervalWrapper {
        interval: CaptureInterval,
    }

    #[test]
    fn test_deserialize_interval_hours() {
        let content = "interval = \"1h\"";
        let wrapper: IntervalWrapper = toml::from_str(content).unwrap();

        let interval = wrapper.interval;
        let expected = CaptureInterval(Interval::Hours(1));

        assert_eq!(interval, expected);
    }

    #[test]
    fn test_deserialize_interval_minutes() {
        let content = "interval = \"1m\"";
        let wrapper: IntervalWrapper = toml::from_str(content).unwrap();

        let interval = wrapper.interval;
        let expected = CaptureInterval(Interval::Minutes(1));

        assert_eq!(interval, expected);
    }

    #[test]
    fn test_deserialize_interval_seconds() {
        let content = "interval = \"1s\"";
        let wrapper: IntervalWrapper = toml::from_str(content).unwrap();

        let interval = wrapper.interval;
        let expected = CaptureInterval(Interval::Seconds(1));

        assert_eq!(interval, expected);
    }

    #[test]
    #[should_panic]
    fn test_missing_size() {
        let content = "interval = \"s\"";
        let wrapper: IntervalWrapper = toml::from_str(content).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_invalid_size() {
        let content = "interval = \"5.5s\"";
        let wrapper: IntervalWrapper = toml::from_str(content).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_missing_unit() {
        let content = "interval = \"5\"";
        let wrapper: IntervalWrapper = toml::from_str(content).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_invalid_unit() {
        let content = "interval = \"5z\"";
        let wrapper: IntervalWrapper = toml::from_str(content).unwrap();
    }
}
